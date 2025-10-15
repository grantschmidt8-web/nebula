// server.js
import express from "express";
import fetch from "node-fetch";
import cheerio from "cheerio";
import path from "path";
import { fileURLToPath } from "url";
import mime from "mime-types";
import helmet from "helmet";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Restrict proxy to allowed hosts (comma-separated) for safety
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || "example.com,mozilla.org, wikipedia.org").split(",").map(s => s.trim()).filter(Boolean);

app.use(helmet({
  contentSecurityPolicy: false // we will handle CSP for proxied content separately
}));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function hostAllowed(hostname) {
  if (ALLOWED_HOSTS.length === 0) return true; // if empty, allow all (dangerous)
  return ALLOWED_HOSTS.some(allowed => {
    if (!allowed) return false;
    // simple containment check to allow subdomains (e.g., allowed "mozilla.org" => "developer.mozilla.org")
    return hostname.endsWith(allowed);
  });
}

function absoluteUrl(base, relative) {
  try {
    return new URL(relative, base).toString();
  } catch (e) {
    return null;
  }
}

// Stream binary assets through the proxy
app.get("/resource", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing url");

  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return res.status(400).send("Invalid url");
  }

  if (!hostAllowed(parsed.hostname)) {
    return res.status(403).send("Host not allowed");
  }

  try {
    const upstream = await fetch(url, {
      headers: {
        // give a benign user-agent
        "user-agent": req.headers["user-agent"] || "node-web-proxy"
      },
      redirect: "follow"
    });

    // forward content-type
    const contentType = upstream.headers.get("content-type");
    if (contentType) res.setHeader("content-type", contentType);
    // forward cache headers optionally:
    const cacheControl = upstream.headers.get("cache-control");
    if (cacheControl) res.setHeader("cache-control", cacheControl);

    // stream body
    upstream.body.pipe(res);
  } catch (err) {
    console.error("Resource fetch error", err);
    res.status(502).send("Bad gateway");
  }
});

// Main HTML proxying endpoint
app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing url param. Usage: /proxy?url=https://example.com");

  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return res.status(400).send("Invalid url");
  }

  if (!hostAllowed(parsed.hostname)) {
    return res.status(403).send("Host not allowed");
  }

  try {
    const upstream = await fetch(url, {
      headers: {
        "user-agent": req.headers["user-agent"] || "node-web-proxy"
      },
      redirect: "follow"
    });

    let contentType = upstream.headers.get("content-type") || "";
    if (!contentType.includes("text/html")) {
      // If not HTML, stream via /resource fallback
      return res.redirect(`/resource?url=${encodeURIComponent(url)}`);
    }

    const html = await upstream.text();

    // parse and rewrite
    const $ = cheerio.load(html, { decodeEntities: false });

    // remove potentially dangerous scripts by default (configurable)
    $("script").remove();

    // remove meta CSP that could block resource loading (we'll serve resources via our proxy)
    $('meta[http-equiv="Content-Security-Policy"]').remove();
    $('meta[http-equiv="content-security-policy"]').remove();

    // rewrite links:
    const attrs = {
      "img": ["src", "srcset"],
      "script": ["src"],
      "link": ["href"],
      "a": ["href"],
      "iframe": ["src"],
      "video": ["src", "poster"],
      "audio": ["src"],
      "source": ["src", "srcset"],
      "form": ["action"]
    };

    Object.keys(attrs).forEach(tag => {
      $(tag).each((i, el) => {
        attrs[tag].forEach(attr => {
          const val = $(el).attr(attr);
          if (!val) return;

          // compute absolute URL
          const abs = absoluteUrl(url, val);
          if (!abs) return;

          // for anchors, keep same-page or hashes local
          if (tag === "a" && (abs === "#" || abs.startsWith("#"))) {
            return;
          }
          // route everything through /resource except HTML pages requested via anchors/forms
          if (tag === "a" || tag === "form" || tag === "iframe") {
            // link to proxied HTML viewer for navigations
            $(el).attr(attr, `/proxy?url=${encodeURIComponent(abs)}`);
          } else {
            // assets -> resource endpoint
            $(el).attr(attr, `/resource?url=${encodeURIComponent(abs)}`);
          }
        });
      });
    });

    // inject a small top bar that provides the original URL and a "open raw" link
    const topbar = `
      <div id="proxy-topbar" style="position:fixed;left:0;right:0;top:0;z-index:2147483647;background:#111;color:#fff;padding:10px 12px;font-family:Arial,Helvetica,sans-serif;display:flex;gap:10px;align-items:center">
        <button id="pb-back" style="padding:6px 10px;border-radius:6px;border:none;background:#333;color:white;cursor:pointer">Back</button>
        <form id="pb-nav" style="display:flex;gap:8px;flex:1" onsubmit="event.preventDefault();location.href='/proxy?url='+encodeURIComponent(document.getElementById('pb-url').value)">
          <input id="pb-url" value="${escapeHtml(url)}" style="flex:1;padding:6px;border-radius:6px;border:1px solid #333;background:#222;color:#fff" />
          <button type="submit" style="padding:6px 10px;border-radius:6px;border:none;background:#2b7cff;color:white;cursor:pointer">Go</button>
        </form>
        <a href="/resource?url=${encodeURIComponent(url)}" style="color:#fff;text-decoration:none;padding:6px 8px;border-radius:6px;background:#333">Open raw</a>
      </div>
      <div style="height:52px"></div>
    `;

    $("body").prepend(topbar);

    // rewrite base tag to current proxy origin to make relative links work (optional)
    $("head").prepend(`<base href="${escapeHtml(parsed.origin + parsed.pathname)}">`);

    // return proxied HTML
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.send($.html());
  } catch (err) {
    console.error("Proxy error", err);
    res.status(502).send("Failed to fetch upstream");
  }
});

// simple API to check host restriction status
app.get("/api/allowed-hosts", (req, res) => {
  res.json({ allowed: ALLOWED_HOSTS });
});

// helper to escape small strings for injection safety
function escapeHtml(str = "") {
  return ("" + str).replace(/[&<>"']/g, (s) => {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return map[s];
  });
}

app.listen(PORT, () => {
  console.log(`Proxy server running on http://localhost:${PORT}`);
  console.log(`Allowed hosts: ${ALLOWED_HOSTS.join(", ")}`);
});
