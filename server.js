/* ==========================================================================
   server.js - Minimal, hardened static file server for the personal website.

   WHY THIS FILE EXISTS
   --------------------
   The site itself is plain HTML, CSS and JavaScript, so it needs no server
   to work. But opening the files directly with file:/// behaves differently
   from a real web server (absolute paths like /css/styles.css break, and
   security headers cannot be tested). This little server gives you the same
   conditions locally that you will get once the site is hosted.

   HOW TO RUN
   ----------
     npm start            (or:  node server.js)
   then open  http://127.0.0.1:3000

   Change the port with an environment variable, e.g.  PORT=8080 node server.js

   IT HAS NO DEPENDENCIES
   ----------------------
   Everything here uses Node's own built-in modules. Nothing is installed
   from npm, so the site has no third-party supply-chain risk: there are no
   packages that can be compromised, and nothing to keep patched.

   SECURITY DESIGN - what this server does and why
   -----------------------------------------------
    1. Read-only. Only GET and HEAD are answered; every other method gets
       405. There is no upload, no form handling, no database and no user
       input that is ever stored or echoed back, which removes whole classes
       of vulnerability (SQL injection, stored XSS, CSRF, mass assignment).
    2. Path traversal is blocked in depth: the URL is decoded, checked for
       null bytes and backslashes, resolved to an absolute path, verified to
       sit inside public/, and then re-verified after symlinks are resolved.
    3. Only files with an extension on an allow-list are served, and each is
       sent with a fixed Content-Type. An unknown extension is a 404, so a
       stray .env, .bak or .key file in public/ could not be downloaded.
    4. Dotfiles (anything starting with ".") are refused, so .git, .env and
       friends are unreachable even if they end up in the served folder.
    5. Every response carries a strict set of security headers, including a
       Content-Security-Policy that forbids inline scripts entirely.
    6. Errors never reveal file paths, stack traces or server internals.
    7. Log lines are sanitised so a crafted URL cannot forge log entries.
    8. It listens on 127.0.0.1 by default, so while you are developing the
       site is not reachable from anywhere else on your network or Wi-Fi.

   BEFORE YOU PUT THIS ON THE PUBLIC INTERNET, read the "GOING LIVE"
   section at the bottom of README.md.
   ========================================================================== */

"use strict";

const http = require("http");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const crypto = require("crypto");


/* ==========================================================================
   CONFIGURATION
   ========================================================================== */

/* The only folder that will ever be served. Resolved once, at startup, to an
   absolute path - every requested file is later checked against this. */
const ROOT = path.resolve(__dirname, "public");

/* Host. 127.0.0.1 means "this computer only".
   Set HOST=0.0.0.0 if you deliberately want to test from your phone on the
   same Wi-Fi - but be aware that exposes the server to your whole network. */
const HOST = process.env.HOST || "127.0.0.1";

/* Port, validated. An invalid or out-of-range PORT falls back to 3000
   instead of crashing or, worse, binding somewhere unexpected. */
const PORT = (function readPort() {
  const raw = Number.parseInt(process.env.PORT || "3000", 10);
  return Number.isInteger(raw) && raw > 0 && raw < 65536 ? raw : 3000;
})();

/* In production mode static assets are cached by the browser for a day.
   In development everything revalidates, so your edits appear immediately. */
const IS_PRODUCTION = process.env.NODE_ENV === "production";

/* Longest URL we will even look at. Anything longer is rejected outright
   rather than being parsed, decoded and resolved. */
const MAX_URL_LENGTH = 2048;

/* The file served when a path does not exist. */
const NOT_FOUND_PAGE = path.join(ROOT, "404.html");


/* ==========================================================================
   MIME TYPE ALLOW-LIST

   This is an allow-list, not a look-up table with a fallback: if an
   extension is not in here, the file is simply not served. That is what
   stops an accidentally-copied secrets file, database dump or source
   archive in public/ from being downloadable.

   Add an entry here if you add a new kind of asset (e.g. ".webm").
   ========================================================================== */
const MIME_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".js":   "text/javascript; charset=utf-8",
  ".svg":  "image/svg+xml",
  ".png":  "image/png",
  ".jpg":  "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".gif":  "image/gif",
  ".ico":  "image/x-icon",
  ".mp4":  "video/mp4",
  ".webm": "video/webm",
  /* HLS streaming: the playlist and the video segments it lists. Needed so
     that seeking works on hosts that do not support HTTP range requests -
     the player fetches whole small segments instead of byte ranges. */
  ".m3u8": "application/vnd.apple.mpegurl",
  ".ts":   "video/mp2t",
  ".woff2": "font/woff2",
  ".txt":  "text/plain; charset=utf-8",
  ".webmanifest": "application/manifest+json",
});

/* Windows treats these basenames as hardware devices, even inside a folder
   and even with an extension added (CON.html is still the console device).
   Opening one can hang the process, so they are refused up front. */
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;


/* ==========================================================================
   SECURITY HEADERS
   Applied to every single response, including errors.
   ========================================================================== */

/* Content-Security-Policy is the most valuable header here. It tells the
   browser exactly which resources this page is allowed to load, so even if
   an attacker did manage to inject markup into a page, the browser would
   refuse to run it.

     default-src 'none'   Deny everything by default, then allow only what
                          the site genuinely needs (a "default deny" policy).
     script-src  'self'   Only scripts served from this origin - and note
                          there is no 'unsafe-inline', so a <script> tag
                          injected into the HTML would NOT execute. This is
                          why every style and script in this project lives in
                          its own file rather than inline in the HTML.
     style-src   'self'   Same for stylesheets.
     img-src     'self'   Images only from this site (no tracking pixels).
     media-src   'self'   Video only from this site.
     font-src    'self'   The site uses system fonts, but this covers you if
                          you self-host a font file later.
     connect-src 'self'   Limits fetch/XMLHttpRequest/WebSocket destinations.
     base-uri    'none'   Blocks an injected <base> tag from re-pointing
                          every relative URL on the page at another server.
     form-action 'none'   There are no forms; this stops an injected one
                          from posting anywhere.
     frame-ancestors 'none'
                          Nobody may put this site in an iframe. Together
                          with X-Frame-Options this defeats clickjacking.
     object-src  'none'   No Flash/Java-era plugin embedding.
     frame-src / worker-src 'none'
                          No iframes and no web workers are used.
*/
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  /* 'self' covers the plain .mp4 files. blob: is required by hls.js: it
     feeds video segments to the player through Media Source Extensions,
     which hands the <video> element a blob: URL rather than a real file
     URL. Without blob: here the browser blocks playback.
     Note this permits only locally-created blobs - it does not allow any
     external origin to supply media. */
  "media-src 'self' blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "worker-src 'none'",
].join("; ");

/* Returns the security headers sent with every response. */
function securityHeaders() {
  const headers = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,

    /* Stops the browser guessing ("sniffing") a file's type from its bytes
       and ignoring our Content-Type. Without it, a file we serve as
       text/plain could be re-interpreted and executed as HTML. */
    "X-Content-Type-Options": "nosniff",

    /* Legacy clickjacking defence for older browsers that predate
       frame-ancestors. */
    "X-Frame-Options": "DENY",

    /* Send only the origin (not the full URL) to other sites, and nothing
       at all when going from HTTPS down to HTTP. */
    "Referrer-Policy": "strict-origin-when-cross-origin",

    /* Explicitly switch off browser features the site never uses, so an
       injected script could not silently ask for the camera or location. */
    "Permissions-Policy":
      "accelerometer=(), autoplay=(), camera=(), display-capture=(), " +
      "encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), " +
      "magnetometer=(), microphone=(), midi=(), payment=(), " +
      "picture-in-picture=(self), usb=(), xr-spatial-tracking=()",

    /* Cross-origin isolation: other origins cannot get a window handle to
       our pages, and cannot load our files as subresources. */
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",

    /* Blocks legacy Adobe crossdomain.xml policy files. */
    "X-Permitted-Cross-Domain-Policies": "none",

    /* No speculative DNS look-ups for third parties (there are none). */
    "X-DNS-Prefetch-Control": "off",
  };

  /* HTTP Strict Transport Security tells browsers to only ever reach this
     site over HTTPS. It is deliberately NOT sent in local development,
     because it would pin http://127.0.0.1 to HTTPS in your browser and make
     other local projects unreachable - an easy mistake to make and an
     annoying one to undo. Enable it only when you deploy behind HTTPS. */
  if (IS_PRODUCTION && process.env.ENABLE_HSTS === "true") {
    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
  }

  return headers;
}


/* ==========================================================================
   HELPERS
   ========================================================================== */

/* Make a string safe to write to the console.

   Log injection: a request for a URL containing newline characters could
   otherwise write extra lines into your log that look like genuine entries
   (or, in a terminal, inject ANSI escape codes that rewrite what you see).
   Every control character is replaced and the result is truncated. */
function safeForLog(value) {
  return String(value)
    .slice(0, 200)
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, "?");
}

/* One log line per request. */
function log(status, method, rawPath) {
  const time = new Date().toISOString().slice(11, 19);
  console.log(`[${time}] ${status} ${safeForLog(method)} ${safeForLog(rawPath)}`);
}

/* Pick the Cache-Control value for a file extension. */
function cacheControlFor(extension) {
  /* HTML is always revalidated so visitors never see a stale page after you
     publish an update. */
  if (extension === ".html") return "no-cache";
  /* Other assets are cached for a day in production. In development nothing
     is cached, so a refresh always shows your latest CSS or JS. */
  return IS_PRODUCTION ? "public, max-age=86400" : "no-cache";
}

/* Build a weak ETag from the file's size and modification time.
   The browser sends it back in If-None-Match; if it still matches we can
   reply "304 Not Modified" with no body at all. The hash means the ETag
   does not leak the exact inode/mtime of the file. */
function makeETag(stats) {
  const source = `${stats.size}-${stats.mtimeMs}`;
  const digest = crypto.createHash("sha1").update(source).digest("base64url");
  return `W/"${digest}"`;
}

/* Send a response that has no file body (errors, redirects, 304s).
   Always includes the security headers. */
function sendStatus(req, res, status, extraHeaders) {
  const headers = Object.assign(
    securityHeaders(),
    { "Content-Length": "0" },
    extraHeaders || {}
  );
  res.writeHead(status, headers);
  res.end();
}

/* Send a short plain-text error page.

   The message is a fixed string chosen by us - it never contains anything
   from the request, so there is nothing for an attacker to reflect back at
   a visitor. */
function sendTextError(req, res, status, message, extraHeaders) {
  const body = Buffer.from(`${status} ${message}\n`, "utf8");
  const headers = Object.assign(
    securityHeaders(),
    {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Length": String(body.length),
      "Cache-Control": "no-store",
    },
    extraHeaders || {}
  );
  res.writeHead(status, headers);
  /* A HEAD request must have identical headers but no body. */
  res.end(req.method === "HEAD" ? undefined : body);
}


/* ==========================================================================
   URL -> FILE PATH

   This is the security-critical part of the server. It converts a URL from
   the internet into a path on disk, and it is where directory traversal
   attacks ("/../../Windows/System32/drivers/etc/hosts") must be stopped.

   Returns { ok: true, filePath } or { ok: false, status, reason }.
   ========================================================================== */
function resolveRequestPath(requestUrl) {
  /* --- Step 1: parse the URL and keep only the path part. --------------
     Using the WHATWG URL parser (rather than string splitting) means the
     query string and fragment are separated off correctly, and "." and ".."
     segments are normalised the same way a browser would do it. The base
     is a throwaway - only the pathname is used. */
  let pathname;
  try {
    pathname = new URL(requestUrl, "http://localhost").pathname;
  } catch (error) {
    return { ok: false, status: 400, reason: "unparsable URL" };
  }

  /* --- Step 2: percent-decode it. --------------------------------------
     "%2e%2e%2f" is "../", so decoding has to happen BEFORE the traversal
     checks, not after. A malformed escape sequence (a lone "%") throws,
     and is answered with 400 rather than being silently repaired. */
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch (error) {
    return { ok: false, status: 400, reason: "bad percent-encoding" };
  }

  /* --- Step 3: reject characters that have no business in a URL path. ---
     - "\0" (null byte) historically truncated file paths in C libraries,
       turning "secret.txt\0.png" into "secret.txt".
     - "\" is a directory separator on Windows, so it is a second, easily
       overlooked route to traversal. */
  if (decoded.includes("\0") || decoded.includes("\\")) {
    return { ok: false, status: 400, reason: "illegal character in path" };
  }

  /* --- Step 4: refuse traversal segments and dotfiles. ------------------
     The URL parser already collapses "..", but this is checked again
     explicitly: defence in depth means never relying on a single control.
     Refusing every segment that starts with "." also keeps .git, .env and
     .htaccess unreachable. */
  const segments = decoded.split("/").filter(Boolean);
  for (const segment of segments) {
    if (segment.startsWith(".")) {
      return { ok: false, status: 404, reason: "dot segment" };
    }
    if (process.platform === "win32" && WINDOWS_RESERVED.test(segment)) {
      return { ok: false, status: 404, reason: "reserved device name" };
    }
  }

  /* --- Step 5: a trailing slash (or "/") means the folder's index page. */
  let relative = segments.join("/");
  if (relative === "" || decoded.endsWith("/")) {
    relative = relative === "" ? "index.html" : `${relative}/index.html`;
  }

  /* --- Step 6: resolve to an absolute path and confirm it is inside
     public/. This is the check that actually enforces the boundary. The
     separator is appended to ROOT so that a sibling folder whose name
     merely starts with the same letters (e.g. "public-backup") cannot
     satisfy the prefix test. */
  const filePath = path.resolve(ROOT, relative);
  if (filePath !== ROOT && !filePath.startsWith(ROOT + path.sep)) {
    return { ok: false, status: 403, reason: "outside web root" };
  }

  return { ok: true, filePath };
}

/* Given a candidate path, find the file to actually serve.

   Handles two conveniences:
     - "/about"  -> "/about.html"   (clean URLs without the extension)
     - a folder  -> its index.html
   and then re-checks the boundary after symlinks are resolved.

   Returns { filePath, stats } or null. */
async function findFile(candidate) {
  const attempts = [candidate];

  /* Allow extensionless URLs such as /anaesthesia-ocr to find the .html
     file. path.extname is empty when there is no extension. */
  if (path.extname(candidate) === "") {
    attempts.push(`${candidate}.html`);
    attempts.push(path.join(candidate, "index.html"));
  }

  for (const attempt of attempts) {
    let stats;
    try {
      /* lstat, not stat: lstat describes the link itself rather than
         following it, so a symlink is noticed here instead of silently
         being followed out of the web root. */
      stats = await fsp.lstat(attempt);
    } catch (error) {
      continue;   /* Does not exist - try the next candidate. */
    }

    /* Resolve any symlinks, then confirm the real file is still inside
       public/. A symlink in public/ pointing at C:\Users\... would be
       caught right here. */
    let realPath;
    try {
      realPath = await fsp.realpath(attempt);
    } catch (error) {
      continue;
    }
    if (realPath !== ROOT && !realPath.startsWith(ROOT + path.sep)) {
      continue;
    }

    /* Re-stat the real target (it may have been a symlink to a file). */
    try {
      stats = await fsp.stat(realPath);
    } catch (error) {
      continue;
    }

    /* Only regular files are served. Directories, sockets, FIFOs and
       Windows device files are all rejected here. */
    if (stats.isFile()) {
      return { filePath: realPath, stats };
    }
  }

  return null;
}


/* ==========================================================================
   RANGE REQUESTS (needed for video seeking)

   When you drag the scrubber on a <video>, the browser asks for a slice of
   the file with a Range header. This parses a single "bytes=start-end"
   range and validates it hard: anything unusual falls back to sending the
   whole file, which is always a safe answer.

   Returns { start, end } | null (send whole file) | "invalid" (416).
   ========================================================================== */
function parseRange(rangeHeader, size) {
  if (typeof rangeHeader !== "string") return null;

  /* Only the "bytes" unit, and only a single range. Multi-range requests
     are rare and add parsing complexity, so they fall back to the full
     file rather than being half-implemented. */
  const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
  if (!match) return null;

  const startText = match[1];
  const endText = match[2];

  /* Guard against absurdly long digit strings before converting. */
  if (startText.length > 15 || endText.length > 15) return "invalid";
  if (startText === "" && endText === "") return null;

  let start;
  let end;

  if (startText === "") {
    /* "bytes=-500" means the LAST 500 bytes. */
    const suffixLength = Number(endText);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return "invalid";
    start = Math.max(0, size - suffixLength);
    end = size - 1;
  } else {
    start = Number(startText);
    end = endText === "" ? size - 1 : Number(endText);
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)) return "invalid";
  }

  /* The range must be non-empty and lie inside the file. */
  if (start < 0 || start >= size || end < start) return "invalid";
  if (end >= size) end = size - 1;

  return { start, end };
}


/* ==========================================================================
   SENDING A FILE
   ========================================================================== */

async function sendFile(req, res, filePath, stats, statusOverride) {
  const extension = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[extension];

  /* Belt and braces: findFile's callers already screen the extension, but
     never serve a file whose type we cannot state with certainty. */
  if (!contentType) {
    return sendTextError(req, res, 404, "Not Found");
  }

  const etag = makeETag(stats);

  const headers = Object.assign(securityHeaders(), {
    "Content-Type": contentType,
    "Cache-Control": cacheControlFor(extension),
    "Last-Modified": stats.mtime.toUTCString(),
    "ETag": etag,
    /* Tells the browser it may ask for byte ranges (video seeking). */
    "Accept-Ranges": "bytes",
  });

  /* --- Conditional request: has the browser already got this version? ---
     If its ETag matches, reply 304 and send no body at all. */
  if (!statusOverride && req.headers["if-none-match"] === etag) {
    res.writeHead(304, headers);
    return res.end();
  }

  /* --- Range request (video seeking) --- */
  const range = statusOverride ? null : parseRange(req.headers.range, stats.size);

  if (range === "invalid") {
    /* Content-Range on a 416 tells the browser how big the file actually is
       so it can retry with a range that exists. */
    return sendTextError(req, res, 416, "Range Not Satisfiable", {
      "Content-Range": `bytes */${stats.size}`,
    });
  }

  const start = range ? range.start : 0;
  const end = range ? range.end : stats.size - 1;
  const length = stats.size === 0 ? 0 : end - start + 1;

  headers["Content-Length"] = String(length);
  if (range) {
    headers["Content-Range"] = `bytes ${start}-${end}/${stats.size}`;
  }

  const status = statusOverride || (range ? 206 : 200);
  res.writeHead(status, headers);

  /* A HEAD request gets the headers only - never a body. */
  if (req.method === "HEAD" || length === 0) {
    return res.end();
  }

  /* Stream the file rather than reading it into memory. A large MP4 would
     otherwise be buffered in full, which is both slow and an easy way for
     several simultaneous requests to exhaust the server's memory. */
  const stream = fs.createReadStream(filePath, { start, end });

  stream.on("error", () => {
    /* The headers have already gone out, so the only correct thing left to
       do is drop the connection. No internal detail is disclosed. */
    res.destroy();
  });

  /* If the visitor navigates away mid-download, close the file handle. */
  res.on("close", () => stream.destroy());

  stream.pipe(res);
}

/* Serve the styled 404 page (falling back to plain text if it is missing). */
async function sendNotFound(req, res) {
  try {
    const stats = await fsp.stat(NOT_FOUND_PAGE);
    if (stats.isFile()) {
      return await sendFile(req, res, NOT_FOUND_PAGE, stats, 404);
    }
  } catch (error) {
    /* Fall through to the plain-text version below. */
  }
  return sendTextError(req, res, 404, "Not Found");
}


/* ==========================================================================
   THE REQUEST HANDLER
   ========================================================================== */

const server = http.createServer(async (req, res) => {
  const rawUrl = req.url || "/";
  let status = 500;

  try {
    /* Nothing sends a request body to this server, but if one arrives it is
       drained so the socket does not stall waiting for it to be read. */
    req.resume();

    /* --- Method check. Read-only server: GET and HEAD only. ------------- */
    if (req.method !== "GET" && req.method !== "HEAD") {
      status = 405;
      /* The Allow header is required on a 405 response. */
      return sendTextError(req, res, 405, "Method Not Allowed", {
        Allow: "GET, HEAD",
      });
    }

    /* --- Reject absurdly long URLs before doing any work on them. ------- */
    if (rawUrl.length > MAX_URL_LENGTH) {
      status = 414;
      return sendTextError(req, res, 414, "URI Too Long");
    }

    /* --- Turn the URL into a safe path inside public/. ------------------ */
    const resolved = resolveRequestPath(rawUrl);
    if (!resolved.ok) {
      status = resolved.status;
      if (resolved.status === 400) {
        return sendTextError(req, res, 400, "Bad Request");
      }
      if (resolved.status === 403) {
        return sendTextError(req, res, 403, "Forbidden");
      }
      return await sendNotFound(req, res);
    }

    /* --- Locate the file on disk. --------------------------------------- */
    const found = await findFile(resolved.filePath);
    if (!found) {
      status = 404;
      return await sendNotFound(req, res);
    }

    /* --- Extension allow-list. ------------------------------------------
       Anything we cannot name a Content-Type for is treated as if it did
       not exist. */
    const extension = path.extname(found.filePath).toLowerCase();
    if (!MIME_TYPES[extension]) {
      status = 404;
      return await sendNotFound(req, res);
    }

    status = 200;
    return await sendFile(req, res, found.filePath, found.stats);

  } catch (error) {
    /* Any unexpected failure becomes a generic 500.

       The details go to the server console for you to debug, and never to
       the visitor: stack traces disclose absolute paths, module versions
       and code structure, all of which are useful to an attacker. */
    console.error("[error]", error && error.message ? error.message : error);
    status = 500;
    if (!res.headersSent) {
      return sendTextError(req, res, 500, "Internal Server Error");
    }
    return res.destroy();

  } finally {
    log(status, req.method, rawUrl);
  }
});


/* ==========================================================================
   DENIAL-OF-SERVICE HARDENING

   Slow-request attacks (Slowloris and friends) work by opening many
   connections and sending headers one byte at a time, holding sockets open
   forever. These timeouts make Node hang up on connections that dawdle.
   ========================================================================== */

/* Time allowed to send the complete request headers. */
server.headersTimeout = 10_000;      /* 10 seconds  */
/* Time allowed for the whole request. */
server.requestTimeout = 30_000;      /* 30 seconds  */
/* How long an idle keep-alive connection is held open. */
server.keepAliveTimeout = 5_000;     /* 5 seconds   */
/* Cap on the number of headers accepted, to bound per-request memory. */
server.maxHeadersCount = 60;

/* Never crash the process on a socket-level error (a client disconnecting
   mid-response is normal, not exceptional). */
server.on("clientError", (error, socket) => {
  if (socket.writable) {
    socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  }
  socket.destroy();
});


/* ==========================================================================
   START UP
   ========================================================================== */

/* Fail clearly if public/ is missing, rather than 404-ing on everything. */
if (!fs.existsSync(ROOT)) {
  console.error(`Cannot start: the folder "${ROOT}" does not exist.`);
  process.exit(1);
}

server.listen(PORT, HOST, () => {
  console.log("");
  console.log("  Patrick Mills - personal website");
  console.log("  ---------------------------------------------");
  console.log(`  Serving:  ${ROOT}`);
  console.log(`  Open:     http://${HOST}:${PORT}`);
  console.log(`  Mode:     ${IS_PRODUCTION ? "production" : "development"}`);
  console.log("  Stop:     press Ctrl+C");
  console.log("");
});

/* A friendly message if the port is already taken (usually another copy of
   this server still running in a different terminal). */
server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use.`);
    console.error(`Try a different one, e.g.:  PORT=3001 node server.js`);
  } else {
    console.error("Server error:", error.message);
  }
  process.exit(1);
});

/* Shut down tidily on Ctrl+C so the port is released immediately. */
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    console.log("\nShutting down...");
    server.close(() => process.exit(0));
    /* If connections refuse to close, exit anyway after 3 seconds. */
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
