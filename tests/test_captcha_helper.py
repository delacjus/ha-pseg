"""Tests for the public CAPTCHA helper page and bookmarklet building."""

from html import unescape
from pathlib import Path
import re
import urllib.parse

from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
import pytest

from custom_components.pseg import captcha_helper
from custom_components.pseg.captcha_helper import (
    HELPER_URL_PATH,
    PsegCaptchaHelperView,
    async_ensure_helper_view,
    render_helper_page,
)

HELPER_SOURCE = (
    "// PSE&G CAPTCHA helper (synthetic test source)\n"
    "(() => {\n"
    "  const label = 'CAPTCHA proof';\n"
    "  console.log(label);\n"
    "})();\n"
)


def _bookmarklet_from_page(page: str) -> str:
    match = re.search(r'href="(javascript:[^"]+)"', page)
    assert match, "helper page must offer a javascript: bookmarklet"
    return urllib.parse.unquote(unescape(match.group(1))[len("javascript:"):])


def test_render_preserves_whole_helper_source() -> None:
    """Newlines, comments and spacing survive the bookmarklet encoding."""
    page = render_helper_page(HELPER_SOURCE)
    assert _bookmarklet_from_page(page) == HELPER_SOURCE
    assert "bookmarks bar" in page
    assert "two minutes" in page
    # Honest about the unverified cross-browser transfer.
    assert "may still refuse" in page


def test_render_without_helper_script_still_gives_instructions() -> None:
    """A missing bundled script degrades to instructions, never to an error page."""
    page = render_helper_page(None)
    assert "javascript:" not in page
    assert "bookmarklet cannot be built" in page
    assert "mysmartenergy.nj.pseg.com" in page


def test_rendered_page_contains_no_account_or_flow_state() -> None:
    """The page is static: no credential, cookie, flow field or proof appears."""
    page = render_helper_page(HELPER_SOURCE)
    for forbidden in (
        "mymeter_",
        "captcha_response",
        "MM_SID",
        "MM_RememberMe",
        "idx=",
        "cookies",
        "secret-proof-value",
    ):
        assert forbidden not in page


def test_shipped_frontend_script_round_trips_through_the_helper_page() -> None:
    """The committed bookmarklet source decodes back to exactly the frontend file."""
    script = Path(captcha_helper.__file__).parent / "frontend" / "pseg-captcha-helper.js"
    if not script.exists():
        pytest.skip("frontend helper script is not present in this checkout")
    source = script.read_text(encoding="utf-8")
    page = render_helper_page(source)
    assert _bookmarklet_from_page(page) == source


async def test_helper_page_is_public_and_builds_bookmarklet(
    hass: HomeAssistant, hass_client_no_auth, monkeypatch, tmp_path: Path
) -> None:
    """An unauthenticated browser can read the page; the proof request is ignored."""
    assert await async_setup_component(hass, "http", {})
    source_path = tmp_path / "helper.js"
    source_path.write_text(HELPER_SOURCE, encoding="utf-8")
    monkeypatch.setattr(captcha_helper, "HELPER_JS_PATH", source_path)

    assert await async_ensure_helper_view(hass) is True
    assert PsegCaptchaHelperView.requires_auth is False

    client = await hass_client_no_auth()
    response = await client.get(f"{HELPER_URL_PATH}?captcha_response=secret-proof-value")
    assert response.status == 200
    assert response.content_type == "text/html"
    page = await response.text()
    assert "PSE&amp;G CAPTCHA helper" in page
    assert _bookmarklet_from_page(page) == HELPER_SOURCE
    assert "secret-proof-value" not in page
    assert response.headers["Cache-Control"] == "no-store"


async def test_helper_page_survives_missing_script(
    hass: HomeAssistant, hass_client_no_auth, monkeypatch, tmp_path: Path
) -> None:
    """A missing bookmarklet file still serves usable instructions."""
    assert await async_setup_component(hass, "http", {})
    monkeypatch.setattr(captcha_helper, "HELPER_JS_PATH", tmp_path / "absent.js")
    assert await async_ensure_helper_view(hass) is True
    client = await hass_client_no_auth()
    response = await client.get(HELPER_URL_PATH)
    assert response.status == 200
    assert "bookmarklet cannot be built" in await response.text()


async def test_helper_view_registration_is_idempotent(hass: HomeAssistant) -> None:
    """Repeated setup (or a flow racing setup) registers the route only once."""
    assert await async_setup_component(hass, "http", {})
    calls = 0
    original = hass.http.register_view

    def counting_register(view):
        nonlocal calls
        calls += 1
        original(view)

    hass.http.register_view = counting_register
    try:
        assert await async_ensure_helper_view(hass) is True
        assert await async_ensure_helper_view(hass) is True
    finally:
        hass.http.register_view = original
    assert calls == 1


async def test_helper_registration_skips_without_http(hass: HomeAssistant) -> None:
    """No HTTP component means no page, and the flow still runs."""
    hass.http = None
    assert await async_ensure_helper_view(hass) is False


@pytest.mark.parametrize("source", [HELPER_SOURCE, None])
def test_bookmarklet_is_a_javascript_url(source: str | None) -> None:
    """A nonempty source always produces a javascript: href, all URL-encoded."""
    if source is None:
        assert "javascript:" not in render_helper_page(None)
        return
    href = _bookmarklet_from_page(render_helper_page(source))
    assert href.startswith("// PSE&G")
