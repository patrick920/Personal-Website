/* ==========================================================================
   tests/check-links.js

   Static analysis of the site's own source files. Where security-tests.js
   attacks the running server, this one reads the HTML, CSS and JavaScript
   on disk and checks them for the mistakes that a static site is actually
   prone to.

   HOW TO RUN
   ----------
     npm run test:links      (or:  node tests/check-links.js)

   WHAT IT CHECKS
   --------------
     1. Every internal link and asset reference points at a file that
        really exists (no broken links on your CV website).
     2. No inline <script> blocks, style="" attributes or on*="" event
        handlers - all three are blocked by the Content-Security-Policy,
        so if one crept in the page would silently stop working.
     3. No javascript: or data: URLs.
     4. Every target="_blank" link carries rel="noopener noreferrer"
        (protection against reverse tabnabbing).
     5. No third-party resources are loaded - the site makes zero external
        requests, so no other company can track your visitors and no CDN
        outage or compromise can affect you.
     6. The JavaScript contains none of the DOM-XSS "sinks" (innerHTML,
        document.write, eval, new Function, insertAdjacentHTML).
     7. Basic page hygiene: a charset, a viewport, a title, a lang
        attribute, exactly one <h1>, and alt text on every image.

   HTML comments are stripped before the checks run, so the commented-out
   <source> lines waiting for your MP4 files are correctly ignored.
   ========================================================================== */

"use strict";

const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const PUBLIC_ROOT = path.join(PROJECT_ROOT, "public");

let passed = 0;
let failed = 0;
const failures = [];

function section(title) {
  console.log(`\n${title}`);
  console.log("-".repeat(title.length));
}

function check(name, condition, detail) {
  if (condition) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    failures.push({ name, detail });
    console.log(`  FAIL  ${name}${detail ? `  (${detail})` : ""}`);
  }
}

/* Collect every file under a folder, recursively. */
function walk(directory, collected = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(full, collected);
    } else {
      collected.push(full);
    }
  }
  return collected;
}

/* Remove HTML comments so that commented-out markup is not analysed. */
function stripComments(html) {
  return html.replace(/<!--[\s\S]*?-->/g, "");
}

/* Remove JavaScript comments, so that a comment merely *mentioning* a
   dangerous function (as the security notes in main.js do) is not mistaken
   for a use of it. A small character scanner is used rather than a regex,
   so that "//" or "/*" appearing inside a string literal is left alone. */
function stripJsComments(source) {
  let output = "";
  let index = 0;
  let quote = null;   /* The quote character we are currently inside, if any */

  while (index < source.length) {
    const char = source[index];
    const next = source[index + 1];

    if (quote) {
      /* Inside a string: copy through, honouring backslash escapes. */
      output += char;
      if (char === "\\") {
        output += next || "";
        index += 2;
        continue;
      }
      if (char === quote) quote = null;
      index++;
      continue;
    }

    if (char === '"' || char === "'" || char === "`") {
      quote = char;
      output += char;
      index++;
      continue;
    }

    if (char === "/" && next === "/") {
      while (index < source.length && source[index] !== "\n") index++;
      continue;
    }

    if (char === "/" && next === "*") {
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) index++;
      index += 2;
      continue;
    }

    output += char;
    index++;
  }

  return output;
}

/* Every tag as raw text, for attribute-level checks. */
function tagsOf(html, tagName) {
  const pattern = new RegExp(`<${tagName}\\b[^>]*>`, "gi");
  return html.match(pattern) || [];
}

function attributeOf(tag, attribute) {
  const match = new RegExp(`${attribute}\\s*=\\s*"([^"]*)"`, "i").exec(tag);
  return match ? match[1] : null;
}


/* ==========================================================================
   RUN
   ========================================================================== */

console.log("=".repeat(64));
console.log("  STATIC SOURCE CHECKS - Patrick Mills personal website");
console.log("=".repeat(64));

const allFiles = walk(PUBLIC_ROOT);
const htmlFiles = allFiles.filter((file) => file.endsWith(".html"));

/* Web-root-relative paths of everything that exists, for link checking. */
const existingPaths = new Set(
  allFiles.map((file) => "/" + path.relative(PUBLIC_ROOT, file).split(path.sep).join("/"))
);

check("public/ contains HTML pages", htmlFiles.length >= 4, `${htmlFiles.length} found`);


/* ------------------------------------------------------------------
   PER-PAGE CHECKS
   ------------------------------------------------------------------ */
for (const file of htmlFiles) {
  const name = path.relative(PROJECT_ROOT, file);
  const rawHtml = fs.readFileSync(file, "utf8");
  const html = stripComments(rawHtml);

  section(`Page: ${name}`);

  /* --- Page hygiene --- */
  check("declares <!DOCTYPE html>", /^<!DOCTYPE html>/i.test(rawHtml.trim()));
  check("sets a lang attribute", /<html[^>]+lang\s*=\s*"/i.test(html));
  check("declares a character set", /<meta\s+charset\s*=\s*"utf-8"/i.test(html));
  check(
    "has a responsive viewport meta tag",
    /<meta[^>]+name\s*=\s*"viewport"[^>]+width=device-width/i.test(html),
    "without this the site will not scale on phones"
  );
  check("has a <title>", /<title>[^<]{3,}<\/title>/i.test(html));

  const h1Count = (html.match(/<h1\b/gi) || []).length;
  check("has exactly one <h1>", h1Count === 1, `${h1Count} found`);

  /* --- Content-Security-Policy compatibility ---
     The CSP forbids inline script and style. Anything caught here would
     be silently blocked by the browser at runtime. */
  const inlineScripts = (html.match(/<script\b(?![^>]*\bsrc\s*=)[^>]*>[\s\S]*?<\/script>/gi) || [])
    .filter((block) => block.replace(/<\/?script[^>]*>/gi, "").trim().length > 0);
  check("no inline <script> blocks", inlineScripts.length === 0, `${inlineScripts.length} found`);

  const inlineStyles = html.match(/\sstyle\s*=\s*"/gi) || [];
  check("no inline style attributes", inlineStyles.length === 0, `${inlineStyles.length} found`);

  const inlineStyleTags = html.match(/<style\b/gi) || [];
  check("no inline <style> blocks", inlineStyleTags.length === 0, `${inlineStyleTags.length} found`);

  /* on*="" attributes are inline JavaScript by another name. */
  const eventHandlers = html.match(/\son[a-z]+\s*=\s*"/gi) || [];
  check("no inline event handler attributes", eventHandlers.length === 0, eventHandlers.join(", "));

  check("no javascript: URLs", !/javascript\s*:/i.test(html));
  check("no data: URLs in href or src", !/(href|src)\s*=\s*"data:/i.test(html));

  /* --- Outbound links --- */
  const anchors = tagsOf(html, "a");
  const blankTargets = anchors.filter((tag) => /target\s*=\s*"_blank"/i.test(tag));
  const unsafeBlanks = blankTargets.filter((tag) => {
    const rel = (attributeOf(tag, "rel") || "").toLowerCase();
    return !rel.includes("noopener") || !rel.includes("noreferrer");
  });
  check(
    'every target="_blank" link has rel="noopener noreferrer"',
    unsafeBlanks.length === 0,
    `${unsafeBlanks.length} unsafe`
  );
  check("page has outbound social links", blankTargets.length >= 2, `${blankTargets.length} found`);

  /* --- No third-party resources --- */
  const externalAssets = [];
  for (const tag of [...tagsOf(html, "script"), ...tagsOf(html, "link"), ...tagsOf(html, "img"), ...tagsOf(html, "source"), ...tagsOf(html, "video")]) {
    const url = attributeOf(tag, "src") || attributeOf(tag, "href") || attributeOf(tag, "poster");
    if (url && /^(https?:)?\/\//i.test(url)) externalAssets.push(url);
  }
  check(
    "loads no third-party resources",
    externalAssets.length === 0,
    externalAssets.join(", ")
  );

  /* --- Images have alt text --- */
  const imagesWithoutAlt = tagsOf(html, "img").filter((tag) => attributeOf(tag, "alt") === null);
  check("every <img> has an alt attribute", imagesWithoutAlt.length === 0, `${imagesWithoutAlt.length} missing`);

  /* --- Internal links and assets resolve --- */
  const references = [];
  const referencePattern = /(?:href|src|poster)\s*=\s*"([^"]+)"/gi;
  let match;
  while ((match = referencePattern.exec(html)) !== null) {
    references.push(match[1]);
  }

  const broken = [];
  for (const reference of references) {
    /* Skip external links, in-page anchors and mail links. */
    if (/^(https?:|mailto:|tel:|#)/i.test(reference)) continue;

    const target = reference.split("#")[0].split("?")[0];
    if (target === "" || target === "/") continue;

    const candidate = target.startsWith("/")
      ? target
      : "/" + path.posix.join(path.posix.dirname("/" + path.relative(PUBLIC_ROOT, file).replace(/\\/g, "/")), target).replace(/^\/+/, "");

    if (!existingPaths.has(candidate) && !existingPaths.has(`${candidate}.html`)) {
      broken.push(reference);
    }
  }
  check("all internal links and assets exist", broken.length === 0, broken.join(", "));

  /* --- Navigation is consistent across pages --- */
  /* Extensionless on purpose. Cloudflare serves /anaesthesia-ocr directly
     and 307-redirects /anaesthesia-ocr.html to it, so linking to the
     extension would cost a redirect on every navigation. server.js resolves
     extensionless URLs too, so local development matches production. */
  const navTargets = [
    "/anaesthesia-ocr",
    "/kanban-pizza-game",
    "/ai-hackathon-2026",
  ];
  const hasNav = navTargets.every((target) => html.includes(`href="${target}"`));
  check("navigation bar links to every page", hasNav);

  check(
    "footer has a LinkedIn and a GitHub link",
    html.includes("LinkedIn Profile") && html.includes("GitHub Profile")
  );
}


/* ------------------------------------------------------------------
   JAVASCRIPT CHECKS
   ------------------------------------------------------------------ */
section("JavaScript: public/js/main.js");

/* Comments are stripped first: main.js explains in its own comments why it
   avoids innerHTML, eval and friends, and those explanations must not be
   read as uses of them. */
const mainJs = stripJsComments(fs.readFileSync(path.join(PUBLIC_ROOT, "js", "main.js"), "utf8"));

/* These are the DOM "sinks" that turn a string into live markup or code.
   Avoiding them entirely is the simplest way to rule out DOM-based XSS. */
const dangerousSinks = [
  ["innerHTML", /\.innerHTML\s*=/],
  ["outerHTML", /\.outerHTML\s*=/],
  ["insertAdjacentHTML", /insertAdjacentHTML\s*\(/],
  ["document.write", /document\s*\.\s*write/],
  ["eval", /\beval\s*\(/],
  ["new Function", /new\s+Function\s*\(/],
  ["setTimeout with a string", /setTimeout\s*\(\s*["'`]/],
  ["setInterval with a string", /setInterval\s*\(\s*["'`]/],
  ["location assignment", /location\s*(\.href)?\s*=/],
];

for (const [label, pattern] of dangerousSinks) {
  check(`main.js does not use ${label}`, !pattern.test(mainJs));
}

check("main.js runs in strict mode", /^\s*"use strict";/.test(mainJs));
check("main.js does not read the URL into the page", !/location\.(search|hash)/.test(mainJs));
check("main.js does not use browser storage", !/(localStorage|sessionStorage|document\.cookie)/.test(mainJs));


/* ------------------------------------------------------------------
   SERVER CHECKS
   ------------------------------------------------------------------ */
section("Server: server.js");

const serverJs = stripJsComments(fs.readFileSync(path.join(PROJECT_ROOT, "server.js"), "utf8"));

/* Confirm every module server.js pulls in is one of Node's own built-ins.
   Anything else would mean an npm package had crept in, bringing with it
   code from someone else that would need keeping patched. */
const NODE_BUILTINS = new Set([
  "http", "https", "fs", "fs/promises", "path", "crypto", "net", "url",
  "zlib", "stream", "os", "events", "util", "buffer",
]);
const requiredModules = [];
const requirePattern = /require\(\s*["']([^"']+)["']\s*\)/g;
let requireMatch;
while ((requireMatch = requirePattern.exec(serverJs)) !== null) {
  requiredModules.push(requireMatch[1].replace(/^node:/, ""));
}
const thirdParty = requiredModules.filter((module) => !NODE_BUILTINS.has(module));
check("server.js requires only Node built-in modules", thirdParty.length === 0, thirdParty.join(", "));

check("server.js binds to localhost by default", /HOST\s*=\s*process\.env\.HOST\s*\|\|\s*"127\.0\.0\.1"/.test(serverJs));
check("server.js restricts methods to GET and HEAD", /!==\s*"GET"\s*&&[\s\S]{0,40}!==\s*"HEAD"/.test(serverJs));
check("server.js sets a Content-Security-Policy", /Content-Security-Policy/.test(serverJs));
check("server.js never uses child_process", !/child_process/.test(serverJs));
check("server.js never uses eval", !/\beval\s*\(/.test(serverJs));
check("server.js checks the resolved path stays inside the web root", /startsWith\(ROOT\s*\+\s*path\.sep\)/.test(serverJs));
check("server.js has request timeouts configured", /headersTimeout|requestTimeout/.test(serverJs));

const packageJson = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "package.json"), "utf8"));
check(
  "package.json declares no runtime dependencies",
  Object.keys(packageJson.dependencies || {}).length === 0
);
check(
  "package.json declares no dev dependencies",
  Object.keys(packageJson.devDependencies || {}).length === 0
);


/* ------------------------------------------------------------------
   DEPLOYED HEADERS: public/_headers must match server.js

   server.js sends the security headers locally, but it is NOT deployed -
   a static host serves public/ directly. public/_headers re-declares them
   for the host. Two copies of the same list will drift apart eventually,
   and the failure is silent: the live site keeps working while quietly
   losing a protection.

   This reads the header NAMES straight out of the securityHeaders()
   function rather than from a hard-coded list here, so adding a header to
   server.js automatically makes this test demand it in _headers too.
   ------------------------------------------------------------------ */
section("Deployed headers: public/_headers vs server.js");

const headersFilePath = path.join(PUBLIC_ROOT, "_headers");

if (!fs.existsSync(headersFilePath)) {
  check("public/_headers exists", false, "needed so the published site keeps its security headers");
} else {
  const headersFile = fs.readFileSync(headersFilePath, "utf8");

  /* Header names declared in _headers: indented "Name: value" lines,
     ignoring comments (#) and path patterns (/...). */
  const declared = new Set(
    headersFile
      .split(/\r?\n/)
      .filter((line) => /^\s+/.test(line) && !/^\s*#/.test(line))
      .map((line) => {
        const colon = line.indexOf(":");
        return colon === -1 ? "" : line.slice(0, colon).trim();
      })
      .filter(Boolean)
  );

  /* Header names set inside securityHeaders() in server.js. Comments are
     already stripped from serverJs, so only real code is scanned. Matches
     both the object-literal form ("Name": value) and the bracket
     assignment form (headers["Name"] = value). */
  const fnStart = serverJs.indexOf("function securityHeaders()");
  const fnBody = fnStart === -1
    ? ""
    : serverJs.slice(fnStart, serverJs.indexOf("return headers;", fnStart));

  const required = [...new Set(
    [...fnBody.matchAll(/"([A-Za-z][A-Za-z-]*-[A-Za-z-]+)"\s*[:\]]/g)].map((m) => m[1])
  )];

  check(
    "securityHeaders() could be parsed out of server.js",
    required.length >= 8,
    `found ${required.length} header names`
  );

  const missing = required.filter((name) => !declared.has(name));
  check(
    "_headers declares every header that server.js sends",
    missing.length === 0,
    missing.length ? `missing: ${missing.join(", ")}` : ""
  );

  /* HSTS is the one header server.js withholds locally on purpose, so it
     has to be added by hand here - it is the easiest one to forget. */
  check(
    "_headers adds Strict-Transport-Security (server.js omits it locally on purpose)",
    declared.has("Strict-Transport-Security")
  );

  check(
    "_headers applies to every path (/*)",
    /^\/\*\s*$/m.test(headersFile),
    "expected a /* path pattern"
  );

  /* The CSP is the one with real substance - make sure the copy in
     _headers did not lose the parts that matter most. */
  const cspLine = headersFile.match(/Content-Security-Policy:\s*(.+)/);
  check("_headers has a Content-Security-Policy", Boolean(cspLine));
  if (cspLine) {
    const csp = cspLine[1];
    for (const directive of [
      "default-src 'none'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'none'",
    ]) {
      check(`_headers CSP keeps ${directive}`, csp.includes(directive));
    }
    check("_headers CSP has no 'unsafe-inline'", !csp.includes("unsafe-inline"));
    check("_headers CSP has no 'unsafe-eval'", !csp.includes("unsafe-eval"));
  }
}


/* ------------------------------------------------------------------
   REPORT
   ------------------------------------------------------------------ */
console.log("\n" + "=".repeat(64));
console.log(`  RESULT: ${passed} passed, ${failed} failed`);
console.log("=".repeat(64));

if (failures.length) {
  console.log("\nFailures:");
  for (const failure of failures) {
    console.log(`  - ${failure.name}${failure.detail ? `: ${failure.detail}` : ""}`);
  }
}

process.exit(failed === 0 ? 0 : 1);
