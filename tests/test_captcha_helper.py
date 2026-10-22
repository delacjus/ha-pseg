"""Tests for the public CAPTCHA helper page and extension archive."""

from html import unescape
import io
from pathlib import Path
import re
import urllib.parse
import zipfile

from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
import pytest

from custom_components.pseg import captcha_helper
from custom_components.pseg.captcha_helper import (
    EXTENSION_MEMBERS,
    EXTENSION_ZIP_FILENAME,
    EXTENSION_ZIP_URL_PATH,
    HELPER_URL_PATH,
    PsegCaptchaExtensionView,
    PsegCaptchaHelperView,
    async_ensure_helper_view,
    build_extension_archive,
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
    assert match, "helper page must still offer the optional bookmarklet fallback"
    return urllib.parse.unquote(unescape(match.group(1))[len("javascript:"):])


def _archive_members(data: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(data))


def test_render_offers_extension_download_before_the_fallback() -> None:
    """The extension is the primary path; the bookmarklet is secondary."""
    page = render_helper_page(HELPER_SOURCE)
    download = page.index("Download helper extension (ZIP)")
    assert download < page.index("Fallback: bookmarklet (unverified)")
    assert f'href="{EXTENSION_ZIP_URL_PATH}"' in page
    assert EXTENSION_ZIP_FILENAME not in page  # the browser names the download
    assert "bookmarks bar" not in page.lower().split("fallback")[0]


def test_render_explains_the_extension_handoff_and_its_limits() -> None:
    """A human gets the load/solve/copy steps and the two-minute proof limit."""
    page = render_helper_page(HELPER_SOURCE)
    for needle in (
        "chrome://extensions",
        "edge://extensions",
        "Developer mode",
        "Load unpacked",
        "https://mysmartenergy.nj.pseg.com",
        "Ready",
        "Copy verification",
        "two minutes",
        "ten minutes",
        "Close helper",
        "blocks the portal's own sign-in request",
        "one desktop browser",
        "not proof of browser acceptance",
    ):
        assert needle in page


def test_render_without_helper_script_still_gives_instructions() -> None:
    """A missing bundled script degrades to instructions, never to an error page."""
    page = render_helper_page(None)
    assert 'href="javascript:' not in page
    assert "bookmarklet cannot be built" in page
    assert "mysmartenergy.nj.pseg.com" in page
    assert f'href="{EXTENSION_ZIP_URL_PATH}"' in page


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


def test_shipped_frontend_script_round_trips_through_the_fallback() -> None:
    """The committed fallback source decodes back to exactly the frontend file."""
    script = Path(captcha_helper.__file__).parent / "frontend" / "pseg-captcha-helper.js"
    if not script.exists():
        pytest.skip("frontend helper script is not present in this checkout")
    source = script.read_text(encoding="utf-8")
    page = render_helper_page(source)
    assert _bookmarklet_from_page(page) == source


def test_shipped_extension_archive_has_exact_flat_membership() -> None:
    """The archive holds exactly the three reviewed files, flat and intact."""
    archive = build_extension_archive()
    assert archive is not None
    with _archive_members(archive) as zf:
        assert zf.namelist() == list(EXTENSION_MEMBERS)
        assert set(zf.namelist()) == {
            "manifest.json",
            "service-worker.js",
            "pseg-captcha-helper.js",
        }
        assert all(not info.is_dir() for info in zf.infolist())
        for name in EXTENSION_MEMBERS:
            assert zf.read(name) == (captcha_helper.EXTENSION_DIR / name).read_bytes()
    assert "pseg-energy-card.js" not in EXTENSION_MEMBERS


def test_extension_archive_is_deterministic() -> None:
    """Fixed member order and timestamps make repeated downloads identical."""
    first = build_extension_archive()
    second = build_extension_archive()
    assert first is not None
    assert first == second


def test_extension_archive_absent_when_any_member_is_missing(
    monkeypatch, tmp_path: Path
) -> None:
    """A partial frontend folder must not produce a ZIP with missing files."""
    monkeypatch.setattr(captcha_helper, "EXTENSION_DIR", tmp_path)
    assert build_extension_archive() is None
    (tmp_path / "manifest.json").write_text("{}", encoding="utf-8")
    assert build_extension_archive() is None


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
    assert f'href="{EXTENSION_ZIP_URL_PATH}"' in page
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


async def test_extension_zip_is_public_fixed_and_ignores_request_data(
    hass: HomeAssistant, hass_client_no_auth
) -> None:
    """An unauthenticated GET gets the same three files; query data is not used."""
    assert await async_setup_component(hass, "http", {})
    assert await async_ensure_helper_view(hass) is True
    assert PsegCaptchaExtensionView.requires_auth is False
    assert PsegCaptchaExtensionView.url == EXTENSION_ZIP_URL_PATH

    client = await hass_client_no_auth()
    response = await client.get(
        f"{EXTENSION_ZIP_URL_PATH}?flow_id=secret-flow&filename=pseg-energy-card.js"
    )
    assert response.status == 200
    assert response.content_type == "application/zip"
    assert (
        response.headers["Content-Disposition"]
        == f'attachment; filename="{EXTENSION_ZIP_FILENAME}"'
    )
    assert response.headers["Cache-Control"] == "no-store"

    # No caller-supplied archive path: only the fixed route serves the ZIP.
    custom_path = await client.get(f"{EXTENSION_ZIP_URL_PATH}/pseg-energy-card.js")
    assert custom_path.status == 404

    body = await response.read()
    assert "secret-flow" not in body.decode("latin-1")
    with _archive_members(body) as zf:
        assert zf.namelist() == list(EXTENSION_MEMBERS)
        assert set(zf.namelist()) == {
            "manifest.json",
            "service-worker.js",
            "pseg-captcha-helper.js",
        }
        for name in EXTENSION_MEMBERS:
            assert zf.read(name) == (
                Path(captcha_helper.__file__).parent / "frontend" / name
            ).read_bytes()


async def test_extension_zip_missing_file_returns_generic_error(
    hass: HomeAssistant, hass_client_no_auth, monkeypatch, tmp_path: Path
) -> None:
    """A missing member yields one generic 404, never a path or file list."""
    assert await async_setup_component(hass, "http", {})
    monkeypatch.setattr(captcha_helper, "EXTENSION_DIR", tmp_path)
    assert await async_ensure_helper_view(hass) is True

    client = await hass_client_no_auth()
    response = await client.get(EXTENSION_ZIP_URL_PATH)
    assert response.status == 404
    assert response.content_type == "text/plain"
    text = await response.text()
    assert text == captcha_helper._MISSING_EXTENSION_TEXT
    assert str(tmp_path) not in text
    assert "manifest.json" not in text
    assert "pseg-captcha-helper.js" not in text


async def test_helper_views_registration_is_idempotent(hass: HomeAssistant) -> None:
    """Repeated setup (or a flow racing setup) registers each route only once."""
    assert await async_setup_component(hass, "http", {})
    registered: list[str] = []
    original = hass.http.register_view

    def counting_register(view):
        registered.append(view.url)
        original(view)

    hass.http.register_view = counting_register
    try:
        assert await async_ensure_helper_view(hass) is True
        assert await async_ensure_helper_view(hass) is True
    finally:
        hass.http.register_view = original
    assert registered == [HELPER_URL_PATH, EXTENSION_ZIP_URL_PATH]


async def test_helper_registration_skips_without_http(hass: HomeAssistant) -> None:
    """No HTTP component means no page, and the flow still runs."""
    hass.http = None
    assert await async_ensure_helper_view(hass) is False


@pytest.mark.parametrize("source", [HELPER_SOURCE, None])
def test_bookmarklet_is_a_javascript_url(source: str | None) -> None:
    """A nonempty source still produces a javascript: href, all URL-encoded."""
    if source is None:
        assert 'href="javascript:' not in render_helper_page(None)
        return
    href = _bookmarklet_from_page(render_helper_page(source))
    assert href.startswith("// PSE&G")
