"""Public CAPTCHA helper page and extension archive for the PSE&G config flow.

Home Assistant cannot solve MyMeter's invisible reCAPTCHA. This page offers the
preferred delivery path: a fixed, public ZIP of the reviewed unpacked browser
extension (``manifest.json``, ``service-worker.js`` and
``pseg-captcha-helper.js``). The user loads it in their own browser, solves the
CAPTCHA on the portal, and copies the one-use proof into the masked Home
Assistant field.

A bookmarklet built from the same helper source stays available as an
explicitly unverified fallback, because the portal's page policy may block a
``javascript:`` bookmark.

The page and the archive are public by design: they carry no flow state,
credentials, cookies, proofs or account data, and read only the three fixed
frontend files. Both routes are registered lazily (once per Home Assistant
instance) so opening a flow works even before the integration has any
configured entry.
"""

from __future__ import annotations

from html import escape
import io
import logging
from pathlib import Path
import urllib.parse
import zipfile

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

HELPER_URL_PATH = "/api/pseg/captcha-helper"
EXTENSION_ZIP_URL_PATH = "/api/pseg/captcha-helper/extension.zip"
EXTENSION_ZIP_FILENAME = "pseg-captcha-helper-extension.zip"
EXTENSION_DIR = Path(__file__).parent / "frontend"
HELPER_JS_PATH = EXTENSION_DIR / "pseg-captcha-helper.js"

# Fixed allowlist: the reviewed extension files only, flat at the archive root.
# pseg-energy-card.js lives in the same folder but is never part of the ZIP, and
# callers cannot add names, flow ids or archive paths.
EXTENSION_MEMBERS: tuple[str, ...] = (
    "manifest.json",
    "service-worker.js",
    "pseg-captcha-helper.js",
)

_REGISTERED_KEY = f"{DOMAIN}_captcha_helper"
_ZIP_REGISTERED_KEY = f"{DOMAIN}_captcha_helper_zip"

_MISSING_EXTENSION_TEXT = "The extension archive is not available from this installation."


def _read_helper_source() -> str | None:
    """Return the bookmarklet source, or None when it was not installed."""
    try:
        return HELPER_JS_PATH.read_text(encoding="utf-8")
    except OSError:
        _LOGGER.debug("CAPTCHA helper bookmarklet source is missing")
        return None


def build_extension_archive() -> bytes | None:
    """Build the fixed in-memory extension ZIP, or None when a member is missing.

    Only ``EXTENSION_MEMBERS`` is read, in that order, so the output is
    deterministic and no caller-supplied name or path can enter the archive. Any
    filesystem failure returns None; the view turns that into one generic message
    that never names a path or file.
    """
    try:
        members = {
            name: (EXTENSION_DIR / name).read_bytes() for name in EXTENSION_MEMBERS
        }
    except OSError:
        _LOGGER.debug("CAPTCHA helper extension files are missing")
        return None

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in EXTENSION_MEMBERS:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, members[name])
    return buffer.getvalue()


def _bookmarklet(source: str) -> str:
    """Encode the whole helper script as a javascript: bookmarklet.

    The full source is URL-encoded (newlines and comments included) so it can ride
    in an href attribute and survive the trip through the browser's address bar.
    """
    return "javascript:" + urllib.parse.quote(source, safe="")


def render_helper_page(source: str | None) -> str:
    """Render the static helper page; never contains flow or account data."""
    if source:
        href = escape(_bookmarklet(source), quote=True)
        fallback_html = (
            f'<p class="install"><a class="bookmarklet" href="{href}">'
            "PSE&amp;G CAPTCHA helper bookmarklet</a></p>"
            '<p class="hint">Drag that button onto your bookmarks bar, or right-click it '
            "and choose <em>Copy link</em>, then create a bookmark whose address is that "
            "link. The portal may block a <code>javascript:</code> bookmark; this fallback "
            "is <strong>unverified</strong>.</p>"
        )
    else:
        fallback_html = (
            '<p class="warn">The helper script is missing from this installation '
            "(<code>custom_components/pseg/frontend/pseg-captcha-helper.js</code>), so "
            "the bookmarklet cannot be built here. Reinstall the integration, or use the "
            "extension download above.</p>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>PSE&amp;G CAPTCHA helper</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 16px/1.55 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         max-width: 46rem; margin: 2rem auto; padding: 0 1rem; }}
  h1 {{ font-size: 1.5rem; }}
  ol {{ padding-left: 1.4rem; }}
  li {{ margin: 0.55rem 0; }}
  code {{ padding: 0.1rem 0.3rem; border-radius: 0.25rem; background: rgba(127,127,127,.18); }}
  .install {{ margin: 1.1rem 0; }}
  .download, .bookmarklet {{ display: inline-block; padding: 0.55rem 1rem;
                  border-radius: 0.4rem; background: #0077cc; color: #fff;
                  text-decoration: none; font-weight: 600; }}
  .download:focus, .download:hover,
  .bookmarklet:focus, .bookmarklet:hover {{ background: #005fa3; }}
  .hint, .note {{ opacity: 0.85; }}
  .warn {{ padding: 0.75rem 1rem; border-left: 4px solid #b35c00;
           background: rgba(179, 92, 0, 0.12); }}
  details {{ margin-top: 1.5rem; }}
</style>
</head>
<body>
<h1>PSE&amp;G CAPTCHA helper</h1>
<p>PSE&amp;G's MyMeter login sometimes asks for a CAPTCHA. Home Assistant cannot
solve it, so you solve it in your own desktop browser and hand the one-time proof
back to Home Assistant.</p>
<div class="install">
  <a class="download" href="{EXTENSION_ZIP_URL_PATH}">Download helper extension (ZIP)</a>
</div>
<p class="hint">The ZIP contains exactly <code>manifest.json</code>,
<code>service-worker.js</code> and <code>pseg-captcha-helper.js</code>. This page
and the ZIP are public and static: they carry no account, cookie, flow or proof
data.</p>
<ol>
  <li><strong>Download and load the extension.</strong> Extract the ZIP to a folder.
      Open <code>chrome://extensions</code> (or <code>edge://extensions</code>), turn
      on <strong>Developer mode</strong>, choose <strong>Load unpacked</strong>, and
      select that folder. Pin "PSE&amp;G verification helper" if you like.</li>
  <li>In another tab, open the exact MyMeter origin
      <code>https://mysmartenergy.nj.pseg.com</code> and click the helper's toolbar
      button. Its panel shows <strong>Ready</strong>; nothing is injected before
      that click.</li>
  <li>Click MyMeter's <strong>Sign In</strong>, then solve the CAPTCHA yourself.
      While the helper is active it blocks the portal's own sign-in request, so the
      proof is not spent.</li>
  <li>Press <strong>Copy verification</strong> in the helper panel before the proof
      expires. <strong>Close helper</strong> removes the panel and restores the
      portal's login; reloading the tab also clears all helper state.</li>
  <li>Return to the Home Assistant dialog, paste the proof into the masked
      <strong>CAPTCHA proof</strong> field, and submit.</li>
</ol>
<p class="note">Google's reCAPTCHA response is valid for only about two minutes,
while Home Assistant keeps the pending sign-in for ten minutes, so capture and
submit promptly. The proof is sent only to PSE&amp;G and is never saved by Home
Assistant. The extension path has been seen working (panel showed Ready, and Close
removed it) on one desktop browser; this is not proof of browser acceptance, of
other browsers, or that PSE&amp;G accepts a proof solved in a different browser.
PSE&amp;G may refuse it, in which case the dialog asks for a fresh proof.</p>
<details>
<summary>Fallback: bookmarklet (unverified)</summary>
<p>Use this only if you cannot load the extension. The portal's page policy may
block a <code>javascript:</code> bookmark, and this path has not been observed on
the live portal.</p>
{fallback_html}
</details>
</body>
</html>
"""


class PsegCaptchaHelperView(HomeAssistantView):
    """Serve the public CAPTCHA helper instructions and extension download."""

    url = HELPER_URL_PATH
    name = "api:pseg:captcha-helper"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Return the static page; no request or flow data is read or echoed."""
        source = await request.app["hass"].async_add_executor_job(_read_helper_source)
        return web.Response(
            text=render_helper_page(source),
            content_type="text/html",
            charset="utf-8",
            headers={"Cache-Control": "no-store"},
        )


class PsegCaptchaExtensionView(HomeAssistantView):
    """Serve the fixed public ZIP of the reviewed helper extension."""

    url = EXTENSION_ZIP_URL_PATH
    name = "api:pseg:captcha-helper-extension"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Build the archive off the event loop; never read request or flow data."""
        archive = await request.app["hass"].async_add_executor_job(
            build_extension_archive
        )
        if archive is None:
            # One generic message: no filesystem path, file list or request data.
            return web.Response(
                status=404,
                text=_MISSING_EXTENSION_TEXT,
                content_type="text/plain",
                charset="utf-8",
                headers={"Cache-Control": "no-store"},
            )
        return web.Response(
            body=archive,
            content_type="application/zip",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{EXTENSION_ZIP_FILENAME}"'
                ),
                "Cache-Control": "no-store",
            },
        )


async def async_ensure_helper_view(hass: HomeAssistant) -> bool:
    """Register the public helper page and ZIP once; True when both are available."""
    if hass.data.get(_REGISTERED_KEY) and hass.data.get(_ZIP_REGISTERED_KEY):
        return True
    http = getattr(hass, "http", None)
    if http is None:
        _LOGGER.debug("HTTP component unavailable; CAPTCHA helper views not registered")
        return False
    if not hass.data.get(_REGISTERED_KEY):
        http.register_view(PsegCaptchaHelperView())
        hass.data[_REGISTERED_KEY] = True
        _LOGGER.debug(
            "Registered the public PSE&G CAPTCHA helper page at %s", HELPER_URL_PATH
        )
    if not hass.data.get(_ZIP_REGISTERED_KEY):
        http.register_view(PsegCaptchaExtensionView())
        hass.data[_ZIP_REGISTERED_KEY] = True
        _LOGGER.debug(
            "Registered the public PSE&G CAPTCHA helper archive at %s",
            EXTENSION_ZIP_URL_PATH,
        )
    return True
