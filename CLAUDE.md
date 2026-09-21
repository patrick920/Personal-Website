# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm start                  # serve public/ at http://127.0.0.1:3000
npm run check              # both test suites (run this before any commit)
npm test                   # tests/security-tests.js  - attacks a live server
npm run test:links         # tests/check-links.js     - static source analysis
```

Port override — PowerShell is the primary shell here, so the syntax differs:

```powershell
$env:PORT=8080; node server.js     # PowerShell
```
```bash
PORT=8080 node server.js           # Git Bash
```

There is no test runner and no per-test filtering: each suite is a single
standalone Node script with a hand-rolled `check()` helper. The two files are
the granularity — to narrow further, comment out a `section()` block. Both
exit non-zero on failure, so they work as CI gates.

`security-tests.js` spawns its own server on port 34567; do not start a server
first. `start-website.bat` is a double-click launcher for the user, not for
agent use.

## Architecture

A static site plus a hardened, **zero-dependency** static file server. Node
built-ins only — `package.json` has empty `dependencies` and `devDependencies`,
and `check-links.js` asserts that both stay empty. Do not add npm packages
without the user explicitly asking; it would break that invariant and the test.

### The web root boundary

`public/` is the entire browser-reachable surface. `server.js`, `package.json`
and `tests/` sit outside it deliberately so they cannot be downloaded. Anything
you add that should not be public must stay outside `public/`.

### The CSP is the central design constraint

`server.js` sends `default-src 'none'` with **no `unsafe-inline`**. This is why:

- all CSS lives in `public/css/styles.css` and all JS in `public/js/main.js`;
- there are no `<style>` blocks, no `style="..."` attributes, and no `on*=""`
  handlers anywhere in the HTML;
- fonts are a system stack, not a webfont — the site makes **zero** external
  requests.

An inline script or style added to a page will be silently blocked by the
browser at runtime. `npm run test:links` fails on all of these, which is the
intended early warning.

### No templating — five HTML files share duplicated markup

The nav bar and footer are copy-pasted across `index.html`,
`anaesthesia-ocr.html`, `kanban-pizza-game.html`, `ai-hackathon-2026.html` and
`404.html`. **A change to either must be made in all five.** The active link is
marked per-file with `aria-current="page"`, which is also what styles it.

`public/css/styles.css` is one file in 11 numbered sections; section 1 is the
design-token block (colours, spacing, radii, fonts). Restyling should happen
there rather than in the rules below it.

### server.js request pipeline

`resolveRequestPath()` → `findFile()` is the security-critical path. It is
deliberately layered, and the redundancy is the point — do not "simplify" it:

1. WHATWG `URL` parse, then `decodeURIComponent` (decoding must precede the
   traversal checks, or `%2e%2e%2f` slips through).
2. Reject null bytes and backslashes (a Windows separator, and a second
   traversal route).
3. Reject dot-prefixed segments and Windows reserved device names
   (`CON.html` still opens the console device).
4. Resolve to an absolute path and check `startsWith(ROOT + path.sep)`.
5. `lstat` + `realpath`, then **re-check containment** — this is what catches a
   symlink or directory junction inside `public/` pointing outside it.

`MIME_TYPES` is an **allow-list, not a lookup with a fallback**: a file whose
extension is absent is served as 404. Adding a new asset type (`.woff`, `.ogg`,
…) requires an entry there or it will silently 404.

Errors are fixed strings that never include anything from the request — the
404 page must never echo the requested URL. Log output passes through
`safeForLog()` to strip control characters.

### Test-suite specifics

`security-tests.js` writes requests directly to a TCP socket because Node's
HTTP client refuses to send some of the deliberately malformed ones. Its
fixtures include a **directory junction pointing at the project root**, so
`removeFixtures()` uses `unlink`/`rmdir` and must never use a recursive delete —
following that link would delete the project.

`check-links.js` strips HTML comments and (via a character scanner that
respects string literals) JavaScript comments before analysing. Both are load-
bearing: the commented-out `<source>` tags awaiting the user's MP4s would
otherwise register as broken links, and `main.js`'s own security notes mention
`innerHTML`, `eval` and `document.write` in prose.

### Video playback (HLS)

Cloudflare's static hosting (Workers Assets) **does not support HTTP range
requests** — a `Range:` GET returns `200` with the entire file and no
`Accept-Ranges`. That breaks `<video>` seeking on a plain `.mp4`. Verified by
measurement, not assumption; don't re-litigate it without re-testing.

The fix avoids needing ranges: each video is also published as HLS under
`public/video/<name>/` (playlist + ~6s segments), and `main.js` attaches
`hls.js` (self-hosted at `public/js/vendor/`, **not** a CDN, so CSP stays
`script-src 'self'`). Load order matters — the vendor script is before
`main.js`, which reads `window.Hls`.

Three deliberate details:
- **hls.js is tried before native HLS.** Chrome returns `canPlayType(...) ===
  "maybe"` for HLS and some builds then fail to play; hls.js's own docs
  recommend this order. Native is the iOS fallback.
- **`enableWorker: false`** so the CSP can keep `worker-src 'none'` (hls.js
  otherwise builds a worker from a `blob:` URL).
- **`media-src 'self' blob:`** in both `server.js` and `_headers` — MSE hands
  the `<video>` a blob URL. This is the one CSP relaxation HLS required.

The `.mp4` files stay in the markup as `<source>` fallbacks so video still
works with JavaScript off. Measured: the browser makes **zero** MP4 requests
when hls.js is active, so they cost nothing on page load.

`server.js` needs `.m3u8` and `.ts` in `MIME_TYPES` or local dev 404s them.

### Deployment

`server.js` is **never deployed** — a static host serves `public/` directly. The
security headers it sends are therefore duplicated in **`public/_headers`** (the
format GitLab Pages / Netlify / Cloudflare Pages all read). `check-links.js` parses
the header names straight out of `securityHeaders()` and fails if any are missing
from `_headers`, so the two cannot drift; add a header to `server.js` and the test
will immediately demand it in `_headers` too.

**Live at `patrickmills.dev`** (and `www.`), hosted on **Cloudflare Workers static
assets**, built from this GitLab repo. `wrangler.jsonc` declares `assets.directory`
= `./public`; its `name` **must** match the deployed Worker (`patrickmills`) or a
manual `wrangler deploy` publishes to a second Worker.

`.gitlab-ci.yml` runs security scans only — no deploy job. GitLab Pages was tried
and abandoned (ignored `_headers`; no range requests). Netlify was prepared and
dropped (bandwidth is metered; Cloudflare's is not).

Verified live: all nine headers plus HSTS (`max-age=31536000`) are served.

Constraints that drove this: **GitHub Pages supports no custom headers at all**, and
**Cloudflare rejects files over 25 MiB** — which is why the OCR video was re-encoded
from 64 MB to 22 MB.

Internal page links are **extensionless** (`/anaesthesia-ocr`, not `.html`).
Cloudflare 307-redirects the `.html` form to the extensionless one, so linking with
the extension would cost a redirect per navigation. `server.js` resolves both, so
local dev matches production.

## Project state

- Real content is in place: both MP4s exist in `public/video/` with their
  `<source>` tags live, and the footer's LinkedIn and GitHub URLs are the
  user's real profiles. (The `<!-- UNCOMMENT THE NEXT LINE -->` comments above
  the two `<source>` tags are now stale leftovers.)
- The home-page hero image is a **portrait-orientation** photo (2296×3561).
  Section 6 of `styles.css` sizes it with `width:auto; height:auto` plus a
  `max-width`/`max-height` pair, so the browser fits it inside those caps
  without ever stretching it. Consequence: it fills the width on phones but
  is a centred ~35% column on desktop. The user chose this over cropping to a
  wide banner — do not "fix" it with `object-fit: cover` unless asked.
- The banner height is capped so it fills most of the first screen but always
  leaves the first lines of the intro paragraph visible. `--hero-banner-max-h`
  (section 1) is `clamp(min, 100vh - space-above - text-peek, cap)` — it
  subtracts the nav/heading/frame above it rather than being a flat `vh`
  percentage, which is what previously let it reach the bottom of the screen.
  Tune it with `--hero-text-peek` (more text shown) or `--hero-banner-cap`.
  An `svh` variant is applied via `@supports`; `svh` is the phone's height
  *with* the address bar showing, i.e. the worst case, so the text still fits
  on first load. `@media (max-height: 32.5em)` in section 10 relaxes the
  reserve for landscape phones by overriding those two custom properties —
  the `clamp()` recalculates itself, so no rule needs duplicating.
- The mobile nav's `transition` lives **only** on the
  `[data-open="true"]` rule, never on the closed state. That is deliberate: a
  transition on the closed state makes the menu animate from its visible
  desktop layout down to hidden whenever the window is resized past the
  breakpoint, so it drops open and fades away on its own. The cost is that
  closing is instant rather than animated. Do not "restore" the closing
  animation by moving the transition back to the base rule.
- Home-page gallery images use `object-fit: contain`, **deliberately**, so the
  whole picture is visible: the three images are different shapes (1.31, 1.90
  and 1.01) and `cover` was cropping all three. The cost is empty space along
  two edges of the 16:10 card box; that is intended, not a bug. The card hover
  is a `filter: brightness()` rather than the old `transform: scale()`, because
  a zoom would crop the image again. Project-page images are exactly 16:9 and
  legitimately use `cover`.
- `.prose` and `.hero__text` have `max-width: none` **deliberately**, so the
  paragraphs line up with the images, videos and cards (everything is a child
  of `.container` and shares its width). They previously had 72ch / 62ch
  reading measures; the user asked for them removed. Do not reinstate a
  max-width "for readability" unless asked.
- HSTS is intentionally off in development — sending it from `http://127.0.0.1`
  would pin every local project on the machine to HTTPS. It is gated behind
  `NODE_ENV=production` **and** `ENABLE_HSTS=true`.
- The site is not deployed. The user has asked to keep it local for now.
