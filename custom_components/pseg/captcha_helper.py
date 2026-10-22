"""Public CAPTCHA helper page for the PSE&G config flow.

Home Assistant cannot solve MyMeter's invisible reCAPTCHA. This page serves a
bookmarklet that wraps the portal's own login submit, captures the one-use proof
the page was about to send, and shows it so the user can copy it into the masked
Home Assistant field.

The page is public by design and carries no flow state, credentials, cookies or
tokens. It is registered lazily (once per Home Assistant instance) so opening a
flow works even before the integration has any configured entry.
"""

from __future__ import annotations

from html import escape
import logging
from pathlib import Path
import urllib.parse

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

HELPER_URL_PATH = "/api/pseg/captcha-helper"
HELPER_JS_PATH = Path(__file__).parent / "frontend" / "pseg-captcha-helper.js"
_REGISTERED_KEY = f"{DOMAIN}_captcha_helper"


def _read_helper_source() -> str | None:
    """Return the bookmarklet source, or None when it was not installed."""
    try:
        return HELPER_JS_PATH.read_text(encoding="utf-8")
    except OSError:
        _LOGGER.debug("CAPTCHA helper bookmarklet source is missing")
        return None


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
        bookmarklet_html = (
            f'<p class="install"><a class="bookmarklet" href="{href}">'
            "PSE&amp;G CAPTCHA helper</a></p>"
            '<p class="hint">Drag that button onto your bookmarks bar. If dragging does '
            "not work, right-click it and choose <em>Copy link</em>, then create a "
            "bookmark whose address is that link.</p>"
        )
    else:
        bookmarklet_html = (
            '<p class="warn">The helper script is missing from this installation '
            "(<code>custom_components/pseg/frontend/pseg-captcha-helper.js</code>), so "
            "the bookmarklet cannot be built here. Reinstall the integration, or copy "
            "the proof from the page source with your browser's developer tools.</p>"
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
  .bookmarklet {{ display: inline-block; padding: 0.55rem 1rem; border-radius: 0.4rem;
                  background: #0077cc; color: #fff; text-decoration: none; font-weight: 600; }}
  .bookmarklet:focus, .bookmarklet:hover {{ background: #005fa3; }}
  .hint, .note {{ opacity: 0.85; }}
  .warn {{ padding: 0.75rem 1rem; border-left: 4px solid #b35c00;
           background: rgba(179, 92, 0, 0.12); }}
</style>
</head>
<body>
<h1>PSE&amp;G CAPTCHA helper</h1>
<p>PSE&amp;G's MyMeter login sometimes asks for a CAPTCHA. Home Assistant cannot
solve it, so you solve it in your own browser and hand the proof back once.</p>
<ol>
  <li>Add the helper button below to your browser's bookmarks bar.
      A desktop browser works best; this page keeps no data.</li>
  <li>In another tab, open
      <code>https://mysmartenergy.nj.pseg.com</code> and wait for the MyMeter
      <strong>Email</strong> / <strong>Password</strong> sign-in page.</li>
  <li>Click the <strong>PSE&amp;G CAPTCHA helper</strong> bookmarklet once. It only
      arms itself; it does not sign you in.</li>
  <li>Click <strong>Sign In</strong> and solve the CAPTCHA yourself.</li>
  <li>The helper holds the proof the page was about to send and stops that
      login request. Press <strong>Copy verification</strong> (or copy the text
      yourself) before the helper window expires.</li>
  <li>Return to the Home Assistant PSE&G dialog, paste it into the masked
      CAPTCHA field, and submit. Google's reCAPTCHA response is only valid for
      about two minutes; Home Assistant keeps the pending sign-in for ten minutes.</li>
</ol>
{bookmarklet_html}
<p class="note">The proof is single-use and Google expires it after about two
minutes, so capture and submit it promptly. Home Assistant drops the pending
sign-in after ten minutes without a proof. The proof is sent only to PSE&amp;G,
is never saved by Home Assistant, and is never shown on this page. This hand-off
is new: PSE&amp;G may still refuse a proof that was solved in a different
browser, in which case the Home Assistant dialog asks for a fresh one.</p>
</body>
</html>
"""


class PsegCaptchaHelperView(HomeAssistantView):
    """Serve the public CAPTCHA helper instructions and bookmarklet."""

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


async def async_ensure_helper_view(hass: HomeAssistant) -> bool:
    """Register the public helper page once; returns True when it is available."""
    if hass.data.get(_REGISTERED_KEY):
        return True
    http = getattr(hass, "http", None)
    if http is None:
        _LOGGER.debug("HTTP component unavailable; CAPTCHA helper page not registered")
        return False
    http.register_view(PsegCaptchaHelperView())
    hass.data[_REGISTERED_KEY] = True
    _LOGGER.debug("Registered the public PSE&G CAPTCHA helper page at %s", HELPER_URL_PATH)
    return True
