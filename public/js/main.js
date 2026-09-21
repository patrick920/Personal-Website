/* ==========================================================================
   main.js - All of the site's client-side behaviour.

   There is deliberately very little JavaScript here. Everything that can be
   done in HTML and CSS is done in HTML and CSS, so the site still works
   perfectly if this file fails to load or JavaScript is switched off.

   What this file does:
     1. Runs the mobile burger menu (open / close / close on Escape /
        close when you click outside it / close when the window is widened).
     2. Fills in the current year in the footer.

   Security notes (important if you extend this file later):
     - Nothing here ever touches innerHTML, outerHTML, document.write, eval
       or new Function. All text is set with textContent, which the browser
       treats as literal text and never as markup. That removes the main
       route to a DOM-based cross-site-scripting (XSS) bug.
     - Nothing here reads the URL, query string or hash and puts it on the
       page, which is the other common source of DOM XSS.
     - Keep it that way: if you need to display a value, use textContent.
   ========================================================================== */

/* "use strict" opts the file into strict mode: typos that would silently
   create global variables become errors instead. */
"use strict";

/* Everything is wrapped in an IIFE (an immediately-invoked function) so that
   none of these variables leak into the global window object. */
(function () {
  /* ------------------------------------------------------------------
     1. MOBILE NAVIGATION MENU
     ------------------------------------------------------------------ */

  /* Grab the elements we need. They are looked up once and reused. */
  var nav = document.querySelector("[data-nav]");
  var toggle = document.querySelector("[data-nav-toggle]");
  var menu = document.querySelector("[data-nav-menu]");

  /* Defensive check: if a page is missing any of these elements, do nothing
     rather than throwing an error that would stop the rest of the script. */
  if (nav && toggle && menu) {
    /* Opens or closes the menu.
       @param {boolean} open - true to open the menu, false to close it. */
    var setMenu = function (open) {
      /* The CSS shows the menu when the <nav> has data-open="true". */
      nav.setAttribute("data-open", open ? "true" : "false");
      /* aria-expanded tells screen readers whether the menu is open.
         Keeping it in step with the visual state is what makes the burger
         menu usable for people relying on assistive technology. */
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    };

    /* Returns true when the menu is currently open. */
    var isOpen = function () {
      return toggle.getAttribute("aria-expanded") === "true";
    };

    /* Start closed. Setting this from JavaScript (rather than in the HTML)
       means the markup stays correct for visitors without JavaScript, who
       simply see the plain list of links. */
    setMenu(false);

    /* --- Click the burger button: flip the menu open or closed. --- */
    toggle.addEventListener("click", function () {
      setMenu(!isOpen());
    });

    /* --- Click one of the links: close the menu.
           Without this, the menu would stay open over the new page on
           browsers that keep the page in memory when you navigate back. --- */
    menu.addEventListener("click", function (event) {
      if (event.target.closest("a")) {
        setMenu(false);
      }
    });

    /* --- Press Escape: close the menu and return focus to the button, so
           a keyboard user is not left with focus in a hidden panel. --- */
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && isOpen()) {
        setMenu(false);
        toggle.focus();
      }
    });

    /* --- Click anywhere outside the nav: close the menu. --- */
    document.addEventListener("click", function (event) {
      if (isOpen() && !nav.contains(event.target)) {
        setMenu(false);
      }
    });

    /* --- Resize the window past the mobile breakpoint: close the menu, so
           the desktop layout never starts out in the "open" state.
           45em matches the breakpoint in styles.css section 10. --- */
    var desktopQuery = window.matchMedia("(min-width: 45.0625em)");
    var handleBreakpoint = function (event) {
      if (event.matches) {
        setMenu(false);
      }
    };

    /* addEventListener on a MediaQueryList is the modern API; addListener is
       the deprecated fallback for older Safari versions. */
    if (typeof desktopQuery.addEventListener === "function") {
      desktopQuery.addEventListener("change", handleBreakpoint);
    } else if (typeof desktopQuery.addListener === "function") {
      desktopQuery.addListener(handleBreakpoint);
    }
  }

  /* ------------------------------------------------------------------
     2. VIDEO PLAYBACK (HLS)

     WHY THIS EXISTS
     Dragging the scrub bar of a plain .mp4 needs the web server to support
     HTTP "range" requests - the browser asks for just the bytes around the
     point you jumped to. Cloudflare's static hosting does not support them:
     it returns the whole file every time, so seeking does not work.

     The fix is to stop needing ranges at all. Each video is also published
     as HLS: dozens of small segment files plus a playlist listing them.
     Seeking then means fetching one small segment, which is an ordinary
     request that every host supports.

     GRACEFUL DEGRADATION - three cases, best first:
       1. Safari and iOS play HLS natively: point the video straight at the
          playlist.
       2. Other browsers: hls.js (self-hosted in js/vendor/) feeds segments
          to the player.
       3. No JavaScript, or hls.js unsupported: the <source> .mp4 already in
          the HTML plays as before. Playback still works; only seeking is
          limited. Nothing here is required for the video to play.
     ------------------------------------------------------------------ */

  var videos = document.querySelectorAll("video[data-hls]");

  for (var v = 0; v < videos.length; v++) {
    (function (video) {
      var playlist = video.getAttribute("data-hls");
      if (!playlist) return;

      /* Case 1: hls.js, which is tried FIRST on purpose.
         The tempting alternative - asking the browser whether it can play
         HLS natively - is unreliable: Chrome answers "maybe" for HLS and
         then, on some builds, cannot actually play it. hls.js's own
         documentation recommends this order for that reason.
         window.Hls exists only on the pages that load the vendored
         library, so this is skipped everywhere else. */
      if (window.Hls && window.Hls.isSupported()) {
        var hls = new window.Hls({
          /* hls.js would normally do its demuxing inside a Web Worker that
             it builds from a blob: URL. This site's Content-Security-Policy
             sets worker-src 'none', and keeping it that way is worth more
             than the small speed gain, so the worker is switched off. */
          enableWorker: false,
          /* Do not pull the whole video down in the background - only what
             is needed to keep playing. */
          maxBufferLength: 30,
        });

        hls.loadSource(playlist);
        hls.attachMedia(video);

        /* If HLS fails for any reason, fall back to the plain .mp4 that is
           still sitting in the markup as a <source> element. */
        hls.on(window.Hls.Events.ERROR, function (event, data) {
          if (data && data.fatal) {
            hls.destroy();
            video.removeAttribute("src");
            video.load();
          }
        });

        return;
      }

      /* Case 2: native HLS. This is the iOS / iPhone path, where Media
         Source Extensions is unavailable so hls.js reports itself
         unsupported, but the browser plays HLS itself. Setting .src
         overrides the <source> element already in the markup. */
      if (video.canPlayType("application/vnd.apple.mpegurl")) {
        video.src = playlist;
        return;
      }

      /* Case 3: nothing to do - the <source> .mp4 in the HTML plays. */
    })(videos[v]);
  }

  /* ------------------------------------------------------------------
     3. FOOTER YEAR
     Keeps the copyright line current without you having to edit four
     HTML files every January.
     ------------------------------------------------------------------ */

  /* There is one [data-year] span per page (in the footer). */
  var yearSlots = document.querySelectorAll("[data-year]");
  var currentYear = String(new Date().getFullYear());

  for (var i = 0; i < yearSlots.length; i++) {
    /* textContent, never innerHTML - see the security notes at the top. */
    yearSlots[i].textContent = currentYear;
  }
})();
