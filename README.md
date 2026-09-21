# Patrick Mills — Personal Website

This is a personal portfolio website showcasing university projects and my Wellington AI Hackathon 2026 win. It was developed using HTML, CSS and JavaScript with Claude Code. It is publicly accessible via: https://patrickmills.dev/

- **Four pages:** Home, Anaesthesia OCR Project, Agile Kanban Pizza Game,
  AI Hackathon 2026.
- **Responsive:** one layout that adapts from a 320px phone up to a large
  desktop monitor, with a burger menu on small screens.
  from a CDN, so there is no third-party code to keep patched and no
  external service that can track visitors or break the site.
- **Security-hardened** and covered by an automated test suite (see
  [Testing](#testing) and [Security](#security)).

---

## Running it on your computer

You need [Node.js](https://nodejs.org/) (version 18 or newer). Check with
`node --version`.

### The easy way

Double-click **`start-website.bat`**. It starts the server and opens
<http://127.0.0.1:3000> in your browser. Close the black console window, or
press `Ctrl+C` in it, to stop.

### From a terminal

```bash
npm start
```

or equivalently:

```bash
node server.js
```

Then open <http://127.0.0.1:3000>.

To use a different port:

```bash
# PowerShell
$env:PORT=8080; node server.js

# Git Bash / macOS / Linux
PORT=8080 node server.js
```

> **Why not just double-click `index.html`?**
> The pages use absolute paths such as `/css/styles.css`, which only resolve
> correctly when served over HTTP. Opening the files directly with `file:///`
> would break the styling and would not let you test the security headers.

---

## Project structure

```
personalwebsite1/
├── server.js               The local web server (heavily commented)
├── package.json            Project metadata and the npm scripts
├── start-website.bat       Double-click launcher for Windows
├── public/                 Everything the server will ever serve
│   ├── index.html              Home page
│   ├── anaesthesia-ocr.html    Anaesthesia OCR Project page
│   ├── kanban-pizza-game.html  Agile Kanban Pizza Game page
│   ├── ai-hackathon-2026.html  AI Hackathon 2026 page
│   ├── 404.html                "Page not found" page
│   ├── favicon.svg             Browser tab icon
│   ├── css/styles.css          All styling (one file, sectioned + commented)
│   ├── js/main.js              Burger menu and footer year
│   ├── images/                 Images and video cover images
│   └── video/                  Put your MP4 files here (see its README.txt)
└── tests/
    ├── security-tests.js   Attacks the running server (139 checks)
    └── check-links.js      Static analysis of the HTML, CSS and JS
```

Only files inside `public/` are ever reachable from a browser. `server.js`,
`package.json` and the tests sit outside it deliberately, so they cannot be
downloaded by a visitor.

---

## Testing

```bash
npm run check      # runs both suites
npm test           # security tests only
npm run test:links # static source checks only
```

Both suites exit with a non-zero status if anything fails, so they can be
added to a CI pipeline later.

**`tests/security-tests.js`** starts its own copy of the server on port
34567, attacks it, and shuts it down. It covers:

| Area | Examples |
|---|---|
| Directory traversal | 16 payloads: `../`, `%2e%2e%2f`, double-encoded, backslash, overlong UTF-8, null byte, absolute paths |
| Access control | dotfiles, non-allow-listed extensions, symlink and directory-junction escapes, directory listings |
| HTTP methods | POST/PUT/DELETE/PATCH/OPTIONS/TRACE rejected; CONNECT cannot open a tunnel |
| Response headers | every header present on 200, 400, 404 and 405 responses; CSP has no `unsafe-inline` |
| Hostile requests | CRLF header injection, request smuggling, forged `Host`, over-long URLs, bad percent-encoding |
| Information disclosure | no stack traces, no file paths, the 404 page never echoes the URL back |
| Correctness | ETag/304, byte ranges for video seeking, correct content types |

**`tests/check-links.js`** reads the source files and checks that every
internal link resolves, that no page contains inline scripts or styles (which
the Content-Security-Policy would block), that every `target="_blank"` link
carries `rel="noopener noreferrer"`, that no third-party resources are
loaded, and that the JavaScript uses none of the DOM-XSS sinks.

Current status: **139 security checks passing** (1 skipped — creating a file
symlink needs administrator rights on Windows; the same escape route is
tested with a directory junction, which does not) and **118 static checks
passing**.

---

## Security

### What the site does not do

Most web vulnerabilities need something this site simply does not have. There
are no forms, no logins, no database, no cookies, no session state, no user
input that is stored or displayed, and no server-side templating. That rules
out SQL injection, stored XSS, CSRF, session fixation, insecure
deserialisation and mass assignment by construction rather than by defence.

### What the server does

`server.js` is commented in detail, but in summary:

- **Read-only.** Only `GET` and `HEAD` are answered; everything else gets
  405.
- **Path traversal blocked in depth.** The URL is decoded, checked for null
  bytes and backslashes, screened for dot segments, resolved to an absolute
  path, confirmed to be inside `public/`, and then confirmed *again* after
  symlinks are resolved.
- **Extension allow-list.** A file is only served if its extension maps to a
  known content type. An `.env`, `.bak` or `.key` file accidentally copied
  into `public/` is not downloadable.
- **Dotfiles refused,** so `.git/`, `.env` and similar stay unreachable.
- **Strict security headers on every response**, including error responses:
  `Content-Security-Policy` (with `default-src 'none'` and no
  `unsafe-inline`), `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy` and `X-Permitted-Cross-Domain-Policies`.
- **No information disclosure.** Errors are fixed strings; stack traces go to
  your console, never to the visitor. The 404 page never echoes the URL.
- **Log injection prevented.** Control characters in a URL are replaced
  before anything is written to the console.
- **Slow-request timeouts** (`headersTimeout`, `requestTimeout`,
  `keepAliveTimeout`) to blunt Slowloris-style attacks.
- **Binds to `127.0.0.1`,** so while you are developing the site is not
  reachable from the rest of your network.

Because the CSP forbids inline script and style, *all* JavaScript and CSS
must stay in `.js` and `.css` files. If you ever add a `<script>` block or a
`style="..."` attribute to a page, the browser will silently refuse to run
it — `npm run test:links` will catch that for you.
