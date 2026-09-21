/* ==========================================================================
   tests/security-tests.js

   An automated security test suite for server.js.

   HOW TO RUN
   ----------
     npm test          (or:  node tests/security-tests.js)

   You do NOT need the server running first - this script starts its own
   copy on a spare port, attacks it, prints a report, then shuts it down.
   It exits with code 0 if everything passed and 1 if anything failed, so
   it can also be wired into a CI pipeline later.

   WHAT IT COVERS
   --------------
     A. Directory traversal (12 encodings and variations)
     B. Access control on sensitive files (dotfiles, unknown extensions,
        files outside the web root, symlink escapes)
     C. HTTP method restrictions
     D. Security response headers, on success AND on error responses
     E. Malformed and hostile requests (null bytes, over-long URLs, bad
        percent-encoding, CRLF header injection, absolute-form URLs)
     F. Information disclosure (no stack traces, no directory listings,
        no reflection of the requested URL into the 404 page)
     G. Correct handling of Range requests, conditional requests and HEAD

   The requests are written straight onto a TCP socket rather than through
   an HTTP client library, because a well-behaved client would refuse to
   send some of these deliberately malformed requests at all.
   ========================================================================== */

"use strict";

const net = require("net");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const PUBLIC_ROOT = path.join(PROJECT_ROOT, "public");
const HOST = "127.0.0.1";
/* A high, unusual port so the tests never collide with a server you are
   already running on 3000. */
const PORT = 34567;

/* Test fixtures created before the run and deleted afterwards. */
const FIXTURES = {
  dotfile: path.join(PUBLIC_ROOT, ".test-secret-config"),
  badExtension: path.join(PUBLIC_ROOT, "test-fixture-secret.bak"),
  outsideRoot: path.join(PROJECT_ROOT, "test-fixture-outside-root.txt"),
  symlink: path.join(PUBLIC_ROOT, "test-fixture-symlink.txt"),
  junction: path.join(PUBLIC_ROOT, "test-fixture-junction"),
};

const SECRET_MARKER = "TOP_SECRET_CANARY_VALUE";

let passed = 0;
let failed = 0;
let skipped = 0;
const failures = [];


/* ==========================================================================
   TINY TEST FRAMEWORK
   ========================================================================== */

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

function skip(name, why) {
  skipped++;
  console.log(`  SKIP  ${name}  (${why})`);
}


/* ==========================================================================
   RAW HTTP CLIENT

   Sends the exact bytes given and parses the raw response. This is what
   lets the suite send requests that Node's own http client would reject.
   ========================================================================== */

function sendRaw(requestBytes) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORT, HOST);
    const chunks = [];
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(parseResponse(Buffer.concat(chunks)));
    };

    socket.setTimeout(5000);
    socket.on("connect", () => socket.write(requestBytes));
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", finish);
    socket.on("close", finish);
    socket.on("timeout", finish);
    socket.on("error", (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

function parseResponse(buffer) {
  const raw = buffer.toString("latin1");
  const separator = raw.indexOf("\r\n\r\n");
  const headText = separator === -1 ? raw : raw.slice(0, separator);
  const body = separator === -1 ? "" : raw.slice(separator + 4);

  const lines = headText.split("\r\n");
  const statusLine = lines[0] || "";
  const statusCode = Number.parseInt(statusLine.split(" ")[1], 10) || 0;

  const headers = {};
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }

  return { statusCode, headers, body, raw, headText, statusLine };
}

/* Convenience wrapper: build a normal GET request for a given raw path. */
function get(rawPath, extraHeaders) {
  const lines = [
    `GET ${rawPath} HTTP/1.1`,
    `Host: ${HOST}:${PORT}`,
    "Connection: close",
  ];
  if (extraHeaders) {
    for (const [key, value] of Object.entries(extraHeaders)) {
      lines.push(`${key}: ${value}`);
    }
  }
  return sendRaw(lines.join("\r\n") + "\r\n\r\n");
}

function requestWithMethod(method, rawPath, extra) {
  const lines = [
    `${method} ${rawPath} HTTP/1.1`,
    `Host: ${HOST}:${PORT}`,
    "Connection: close",
  ];
  if (extra) lines.push(extra);
  return sendRaw(lines.join("\r\n") + "\r\n\r\n");
}


/* ==========================================================================
   SERVER LIFECYCLE
   ========================================================================== */

function startServer() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(PROJECT_ROOT, "server.js")], {
      cwd: PROJECT_ROOT,
      env: Object.assign({}, process.env, { PORT: String(PORT), HOST }),
      stdio: ["ignore", "pipe", "pipe"],
    });

    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("The server did not start within 10 seconds."));
    }, 10000);

    child.stdout.on("data", (data) => {
      if (data.toString().includes("Open:")) {
        clearTimeout(timer);
        resolve(child);
      }
    });

    child.stderr.on("data", (data) => {
      process.stderr.write(`[server] ${data}`);
    });

    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function createFixtures() {
  const created = { symlink: false, junction: false };

  /* A dotfile inside public/ - must never be served. */
  fs.writeFileSync(FIXTURES.dotfile, `${SECRET_MARKER} dotfile\n`);

  /* A file with an extension that is not on the allow-list. */
  fs.writeFileSync(FIXTURES.badExtension, `${SECRET_MARKER} backup\n`);

  /* A file OUTSIDE the web root - the target of the traversal tests. */
  fs.writeFileSync(FIXTURES.outsideRoot, `${SECRET_MARKER} outside root\n`);

  /* A symlink inside public/ that points outside it. Creating symlinks on
     Windows normally needs Developer Mode or an elevated prompt, so this
     one is allowed to fail and the matching test is skipped. */
  try {
    fs.symlinkSync(FIXTURES.outsideRoot, FIXTURES.symlink, "file");
    created.symlink = true;
  } catch (error) {
    created.symlink = false;
  }

  /* A directory JUNCTION inside public/ pointing at the whole project
     folder. Junctions are the Windows equivalent of a directory symlink and,
     unlike file symlinks, creating one needs no special privileges - so this
     escape route can be tested properly on an ordinary Windows account. */
  try {
    fs.symlinkSync(PROJECT_ROOT, FIXTURES.junction, "junction");
    created.junction = true;
  } catch (error) {
    created.junction = false;
  }

  return created;
}

function removeFixtures() {
  for (const file of Object.values(FIXTURES)) {
    /* Deliberately NEVER a recursive delete. The junction fixture points at
       the whole project folder, and a recursive remove that followed it
       would delete the project. unlink (and, as a fallback, rmdir) remove
       the link itself and never touch what it points at. */
    try {
      fs.unlinkSync(file);
      continue;
    } catch (error) {
      /* Not a plain file - try the directory-link form below. */
    }
    try {
      fs.rmdirSync(file);
    } catch (error) {
      /* Already gone, or never created - nothing to do. */
    }
  }
}


/* ==========================================================================
   THE TESTS
   ========================================================================== */

async function runTests(fixtureState) {

  /* ------------------------------------------------------------------
     SANITY: the site itself must actually work.
     ------------------------------------------------------------------ */
  section("0. Baseline - the site works");

  const home = await get("/");
  check("GET / returns 200", home.statusCode === 200, `got ${home.statusCode}`);
  check(
    "GET / returns the home page",
    home.body.includes("Patrick Mills") && home.body.includes("University Projects"),
    "expected content missing"
  );
  check(
    "GET / is served as HTML",
    (home.headers["content-type"] || "").startsWith("text/html"),
    home.headers["content-type"]
  );

  for (const page of [
    "/anaesthesia-ocr.html",
    "/kanban-pizza-game.html",
    "/ai-hackathon-2026.html",
    "/css/styles.css",
    "/js/main.js",
    "/images/portrait-image.jpg",
    "/favicon.svg",
  ]) {
    const response = await get(page);
    check(`GET ${page} returns 200`, response.statusCode === 200, `got ${response.statusCode}`);
  }

  const clean = await get("/anaesthesia-ocr");
  check("Extensionless URL /anaesthesia-ocr resolves", clean.statusCode === 200, `got ${clean.statusCode}`);


  /* ------------------------------------------------------------------
     A. DIRECTORY TRAVERSAL

     Each of these tries to read the fixture file that sits one level
     above public/. A pass means the server refused (4xx) AND the secret
     marker does not appear anywhere in the response.
     ------------------------------------------------------------------ */
  section("A. Directory traversal");

  const traversalPayloads = [
    ["plain ../",                  "/../test-fixture-outside-root.txt"],
    ["deep ../../../",             "/../../../test-fixture-outside-root.txt"],
    ["encoded %2e%2e%2f",          "/%2e%2e%2ftest-fixture-outside-root.txt"],
    ["encoded slash %2f",          "/..%2ftest-fixture-outside-root.txt"],
    ["double-encoded %252e%252e",  "/%252e%252e%252ftest-fixture-outside-root.txt"],
    ["backslash ..\\",             "/..\\test-fixture-outside-root.txt"],
    ["encoded backslash %5c",      "/..%5ctest-fixture-outside-root.txt"],
    ["overlong UTF-8 %c0%af",      "/..%c0%aftest-fixture-outside-root.txt"],
    ["mixed ....//",               "/....//test-fixture-outside-root.txt"],
    ["nested subdir escape",       "/images/../../test-fixture-outside-root.txt"],
    ["absolute Windows path",      "/C:/Windows/win.ini"],
    ["absolute POSIX path",        "//etc/passwd"],
    ["UNC-style path",             "/%5C%5C127.0.0.1%5Cshare"],
    ["null byte truncation",       "/index.html%00.png"],
    ["traversal to server.js",     "/../server.js"],
    ["traversal to package.json",  "/../package.json"],
  ];

  for (const [label, payload] of traversalPayloads) {
    const response = await get(payload);
    const blocked = response.statusCode >= 400;
    const noLeak = !response.body.includes(SECRET_MARKER);
    check(
      `traversal blocked: ${label}`,
      blocked && noLeak,
      `status ${response.statusCode}${noLeak ? "" : ", SECRET LEAKED"}`
    );
  }

  /* Files that legitimately live outside public/ must not be reachable by
     their normal names either. */
  for (const target of ["/server.js", "/package.json", "/tests/security-tests.js", "/README.md", "/.git/config"]) {
    const response = await get(target);
    check(
      `${target} is not served`,
      response.statusCode === 404 && !response.body.includes("createServer"),
      `got ${response.statusCode}`
    );
  }


  /* ------------------------------------------------------------------
     B. ACCESS CONTROL ON SENSITIVE FILES
     ------------------------------------------------------------------ */
  section("B. Access control");

  const dotfile = await get("/.test-secret-config");
  check(
    "dotfile inside public/ is refused",
    dotfile.statusCode === 404 && !dotfile.body.includes(SECRET_MARKER),
    `got ${dotfile.statusCode}`
  );

  const badExtension = await get("/test-fixture-secret.bak");
  check(
    "file with a non-allow-listed extension is refused",
    badExtension.statusCode === 404 && !badExtension.body.includes(SECRET_MARKER),
    `got ${badExtension.statusCode}`
  );

  if (fixtureState.symlink) {
    const symlink = await get("/test-fixture-symlink.txt");
    check(
      "symlink pointing outside the web root is refused",
      symlink.statusCode === 404 && !symlink.body.includes(SECRET_MARKER),
      `got ${symlink.statusCode}`
    );
  } else {
    skip("symlink pointing outside the web root is refused", "file symlinks need admin rights on Windows");
  }

  if (fixtureState.junction) {
    /* The junction makes the entire project folder appear inside public/.
       Every one of these must be refused, because the real file each one
       resolves to lives outside the web root. */
    for (const target of [
      "/test-fixture-junction/server.js",
      "/test-fixture-junction/package.json",
      "/test-fixture-junction/test-fixture-outside-root.txt",
      "/test-fixture-junction/tests/security-tests.js",
    ]) {
      const response = await get(target);
      check(
        `directory junction escape refused: ${target}`,
        response.statusCode === 404 &&
          !response.body.includes(SECRET_MARKER) &&
          !response.body.includes("createServer"),
        `got ${response.statusCode}`
      );
    }
  } else {
    skip("directory junction escape is refused", "could not create a junction");
  }

  /* Directory listing: asking for a folder must not enumerate its files.

     Note that a pass here means "404, and no file names from that folder
     were listed". The 404 page legitimately references /css/styles.css in
     its own <link> tag, so the check looks for the *contents* of the
     requested folder rather than for any mention of a file name. */
  const imagesDir = await get("/images/");
  const imageNames = ["portrait-image", "award-hackathon", "video-poster-ocr"];
  check(
    "no directory listing for /images/",
    imagesDir.statusCode === 404 && !imageNames.some((name) => imagesDir.body.includes(name)),
    `got ${imagesDir.statusCode}`
  );

  const cssDir = await get("/css");
  check(
    "no directory listing for /css",
    cssDir.statusCode === 404 && !/index of|<li>[^<]*\.css/i.test(cssDir.body),
    `got ${cssDir.statusCode}`
  );

  const jsDir = await get("/js/");
  check(
    "no directory listing for /js/",
    jsDir.statusCode === 404 && !/index of|<li>[^<]*\.js\b/i.test(jsDir.body),
    `got ${jsDir.statusCode}`
  );


  /* ------------------------------------------------------------------
     C. HTTP METHODS
     A read-only server should answer only GET and HEAD.
     ------------------------------------------------------------------ */
  section("C. HTTP methods");

  for (const method of ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]) {
    const response = await requestWithMethod(method, "/", "Content-Length: 0");
    check(
      `${method} is rejected with 405`,
      response.statusCode === 405,
      `got ${response.statusCode}`
    );
  }

  /* CONNECT is the method a client uses to ask a server to open a tunnel to
     somewhere else. Node routes it to a separate "connect" event rather than
     to the request handler, and because this server registers no listener
     for that event, Node simply drops the connection (status 0 here). That
     is the outcome we want: the server cannot be abused as an open proxy.
     The test accepts either a dropped connection or a 405. */
  const connect = await requestWithMethod("CONNECT", "example.com:443");
  check(
    "CONNECT cannot be used to open a tunnel (no open proxy)",
    connect.statusCode === 0 || connect.statusCode === 405,
    `got ${connect.statusCode}`
  );
  check(
    "CONNECT does not return a 2xx tunnel-established response",
    !(connect.statusCode >= 200 && connect.statusCode < 300),
    connect.statusLine
  );

  const methodNotAllowed = await requestWithMethod("POST", "/", "Content-Length: 0");
  check(
    "405 response includes an Allow header",
    (methodNotAllowed.headers["allow"] || "").includes("GET"),
    methodNotAllowed.headers["allow"]
  );

  /* TRACE in particular must not echo the request back (Cross-Site
     Tracing / XST, which can be used to read otherwise-hidden headers). */
  const trace = await requestWithMethod("TRACE", "/", "X-Canary: CANARY123");
  check(
    "TRACE does not echo request headers back",
    !trace.body.includes("CANARY123"),
    "request echoed"
  );

  const head = await requestWithMethod("HEAD", "/");
  check("HEAD is allowed", head.statusCode === 200, `got ${head.statusCode}`);
  check("HEAD returns no body", head.body.length === 0, `${head.body.length} bytes returned`);


  /* ------------------------------------------------------------------
     D. SECURITY HEADERS
     These must be present on error responses too, not just on 200s -
     error pages are just as capable of being attacked.
     ------------------------------------------------------------------ */
  section("D. Security headers");

  const headerTargets = [
    ["200 HTML", await get("/")],
    ["200 CSS", await get("/css/styles.css")],
    ["404", await get("/does-not-exist")],
    ["405", await requestWithMethod("POST", "/", "Content-Length: 0")],
    ["400", await get("/%")],
  ];

  const requiredHeaders = [
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "x-permitted-cross-domain-policies",
  ];

  for (const [label, response] of headerTargets) {
    for (const header of requiredHeaders) {
      check(
        `${label} response sets ${header}`,
        Boolean(response.headers[header]),
        "header missing"
      );
    }
  }

  const csp = home.headers["content-security-policy"] || "";
  check("CSP uses default-src 'none'", csp.includes("default-src 'none'"), csp);
  check("CSP has no 'unsafe-inline'", !csp.includes("unsafe-inline"), csp);
  check("CSP has no 'unsafe-eval'", !csp.includes("unsafe-eval"), csp);
  check("CSP has no wildcard source", !csp.includes(" *"), csp);
  check("CSP sets frame-ancestors 'none'", csp.includes("frame-ancestors 'none'"), csp);
  check("CSP sets object-src 'none'", csp.includes("object-src 'none'"), csp);
  check("CSP sets base-uri 'none'", csp.includes("base-uri 'none'"), csp);

  check(
    "X-Content-Type-Options is nosniff",
    home.headers["x-content-type-options"] === "nosniff",
    home.headers["x-content-type-options"]
  );
  check(
    "X-Frame-Options is DENY",
    home.headers["x-frame-options"] === "DENY",
    home.headers["x-frame-options"]
  );
  check(
    "no Server header is advertised",
    !home.headers["server"],
    home.headers["server"]
  );
  check(
    "no X-Powered-By header is advertised",
    !home.headers["x-powered-by"],
    home.headers["x-powered-by"]
  );
  check(
    "HSTS is not sent over plain HTTP in development",
    !home.headers["strict-transport-security"],
    "HSTS on localhost would break other local sites"
  );


  /* ------------------------------------------------------------------
     E. MALFORMED AND HOSTILE REQUESTS
     ------------------------------------------------------------------ */
  section("E. Malformed and hostile requests");

  const badEncoding = await get("/%zz");
  check("malformed percent-encoding returns 400", badEncoding.statusCode === 400, `got ${badEncoding.statusCode}`);

  const loneCent = await get("/%");
  check("lone percent sign returns 400", loneCent.statusCode === 400, `got ${loneCent.statusCode}`);

  const longUrl = await get("/" + "a".repeat(4000));
  check("over-long URL returns 414", longUrl.statusCode === 414, `got ${longUrl.statusCode}`);

  /* CRLF / response-splitting: if the requested path were echoed into a
     response header unescaped, this would create extra headers or a second
     response. The pass condition is that no injected header appears. */
  const crlf = await get("/%0d%0aX-Injected:%20yes");
  check(
    "CRLF in the URL cannot inject a response header",
    !/x-injected/i.test(crlf.headText),
    "header injected"
  );
  check(
    "CRLF request does not produce a split response",
    (crlf.raw.match(/HTTP\/1\.1 \d\d\d/g) || []).length === 1,
    "multiple status lines seen"
  );

  /* Absolute-form request line (what a proxy would send). The server must
     still only serve from its own web root. */
  const absoluteForm = await sendRaw(
    `GET http://evil.example.com/../test-fixture-outside-root.txt HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\nConnection: close\r\n\r\n`
  );
  check(
    "absolute-form request cannot escape the web root",
    absoluteForm.statusCode >= 400 && !absoluteForm.body.includes(SECRET_MARKER),
    `got ${absoluteForm.statusCode}`
  );

  /* A forged Host header must not change what is served or appear in the
     response (Host-header injection / cache poisoning). */
  const forgedHost = await get("/", { Host: "evil.example.com" });
  check(
    "forged Host header does not appear in the response",
    !forgedHost.raw.includes("evil.example.com"),
    "host reflected"
  );

  /* A request body on a GET must be ignored, not parsed. */
  const bodyOnGet = await sendRaw(
    `GET / HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello`
  );
  check("GET with a body is handled safely", bodyOnGet.statusCode === 200, `got ${bodyOnGet.statusCode}`);

  /* Request smuggling shape: conflicting Content-Length and
     Transfer-Encoding headers must not be accepted. */
  const smuggle = await sendRaw(
    `GET / HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n`
  );
  check(
    "conflicting Content-Length + Transfer-Encoding is rejected",
    smuggle.statusCode === 400 || smuggle.statusCode === 0,
    `got ${smuggle.statusCode}`
  );

  /* A URL packed with control characters must not crash the server or be
     written raw into the logs. */
  const controlChars = await get("/%01%02%03%1b%5b31m");
  check(
    "control characters in the URL are handled",
    controlChars.statusCode >= 400 && controlChars.statusCode < 500,
    `got ${controlChars.statusCode}`
  );

  /* The server must still be alive after all of the above. */
  const stillAlive = await get("/");
  check("server survived every malformed request", stillAlive.statusCode === 200, `got ${stillAlive.statusCode}`);


  /* ------------------------------------------------------------------
     F. INFORMATION DISCLOSURE
     ------------------------------------------------------------------ */
  section("F. Information disclosure");

  const notFound = await get("/this-page-does-not-exist");
  check("unknown path returns 404", notFound.statusCode === 404, `got ${notFound.statusCode}`);
  check(
    "404 page does not echo the requested URL",
    !notFound.body.includes("this-page-does-not-exist"),
    "URL reflected into the page"
  );

  /* Reflected XSS attempt: the payload must not come back in the body. */
  const xss = await get("/%3Cscript%3Ealert(1)%3C%2Fscript%3E");
  check(
    "XSS payload in the URL is not reflected",
    !xss.body.includes("<script>alert(1)</script>") && !xss.body.includes("alert(1)"),
    "payload reflected"
  );

  const errorResponses = [notFound, badEncoding, longUrl, methodNotAllowed];
  for (const response of errorResponses) {
    const leaks = /at\s+\w+\s+\(|node_modules|[A-Z]:\\Users|\/home\/|ENOENT|Error:/.test(response.body);
    check(
      `${response.statusCode} error page leaks no internals`,
      !leaks,
      "stack trace or path disclosed"
    );
  }

  check(
    "404 page leaks no absolute file paths",
    !/[A-Za-z]:\\|\/Users\//.test(notFound.body),
    "path disclosed"
  );


  /* ------------------------------------------------------------------
     G. CORRECTNESS: caching, ranges, content types
     ------------------------------------------------------------------ */
  section("G. Caching, ranges and content types");

  check("responses carry an ETag", Boolean(home.headers["etag"]), "no ETag");

  const conditional = await get("/", { "If-None-Match": home.headers["etag"] });
  check("matching If-None-Match returns 304", conditional.statusCode === 304, `got ${conditional.statusCode}`);
  check("304 response has no body", conditional.body.length === 0, `${conditional.body.length} bytes`);

  const staleEtag = await get("/", { "If-None-Match": 'W/"not-the-right-etag"' });
  check("stale If-None-Match returns the file", staleEtag.statusCode === 200, `got ${staleEtag.statusCode}`);

  check(
    "HTML is served with no-cache so updates appear immediately",
    (home.headers["cache-control"] || "").includes("no-cache"),
    home.headers["cache-control"]
  );

  const partial = await get("/css/styles.css", { Range: "bytes=0-99" });
  check("valid Range returns 206", partial.statusCode === 206, `got ${partial.statusCode}`);
  check("206 returns exactly the bytes asked for", partial.body.length === 100, `${partial.body.length} bytes`);
  check(
    "206 sets Content-Range",
    (partial.headers["content-range"] || "").startsWith("bytes 0-99/"),
    partial.headers["content-range"]
  );

  const badRange = await get("/css/styles.css", { Range: "bytes=99999999-99999999" });
  check("out-of-bounds Range returns 416", badRange.statusCode === 416, `got ${badRange.statusCode}`);

  const nonsenseRange = await get("/css/styles.css", { Range: "bytes=abc-def" });
  check("unparsable Range falls back to 200", nonsenseRange.statusCode === 200, `got ${nonsenseRange.statusCode}`);

  const hugeRange = await get("/css/styles.css", { Range: "bytes=0-99999999999999999999999" });
  check(
    "absurd Range value is handled safely",
    hugeRange.statusCode === 206 || hugeRange.statusCode === 416 || hugeRange.statusCode === 200,
    `got ${hugeRange.statusCode}`
  );

  const contentTypes = [
    ["/css/styles.css", "text/css"],
    ["/js/main.js", "text/javascript"],
    ["/favicon.svg", "image/svg+xml"],
    ["/", "text/html"],
  ];
  for (const [target, expected] of contentTypes) {
    const response = await get(target);
    check(
      `${target} has Content-Type ${expected}`,
      (response.headers["content-type"] || "").startsWith(expected),
      response.headers["content-type"]
    );
  }
}


/* ==========================================================================
   MAIN
   ========================================================================== */

(async function main() {
  console.log("=".repeat(64));
  console.log("  SECURITY TEST SUITE - Patrick Mills personal website");
  console.log("=".repeat(64));

  removeFixtures();
  const fixtureState = createFixtures();

  let child;
  try {
    child = await startServer();
    await runTests(fixtureState);
  } catch (error) {
    failed++;
    failures.push({ name: "test harness", detail: error.message });
    console.error("\nThe test run stopped early:", error.message);
  } finally {
    if (child) child.kill();
    removeFixtures();
  }

  console.log("\n" + "=".repeat(64));
  console.log(`  RESULT: ${passed} passed, ${failed} failed, ${skipped} skipped`);
  console.log("=".repeat(64));

  if (failures.length) {
    console.log("\nFailures:");
    for (const failure of failures) {
      console.log(`  - ${failure.name}${failure.detail ? `: ${failure.detail}` : ""}`);
    }
  }

  process.exit(failed === 0 ? 0 : 1);
})();
