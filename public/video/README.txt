Put your MP4 video files in this folder.

Suggested names (these match the commented-out <source> lines in the HTML):

  ocr-demo.mp4        -> used by public/anaesthesia-ocr.html
  hackathon-demo.mp4  -> used by public/ai-hackathon-2026.html

After copying a file in here, open the matching HTML page and remove the
comment markers from around its <source> line, so that:

  <!-- <source src="/video/ocr-demo.mp4" type="video/mp4"> -->

becomes:

  <source src="/video/ocr-demo.mp4" type="video/mp4">

Notes
-----
* Only .mp4 and .webm are on the server's allow-list of servable file
  types. To serve another format, add its extension and MIME type to the
  MIME_TYPES list in server.js.
* Keep files reasonably small (a few tens of MB at most). Large videos are
  slow to load for visitors on mobile data.
* H.264 video with AAC audio in an .mp4 container plays in every current
  browser.
* The still image shown before the visitor presses play comes from the
  poster="..." attribute on the <video> tag, not from the video file.
