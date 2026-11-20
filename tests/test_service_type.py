"""Tests for selecting the electric service before fetching usage."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from custom_components.pseg.const import PORTAL_URL_LI, PORTAL_URL_NJ
from custom_components.pseg.pseg_client import PsegClient, PsegTransientError

# Literals on purpose: the tests must fail on behavior, not on a missing constant.
SERVICE_TYPE_ELECTRIC = 1
SERVICE_TYPE_URL = "/Dashboard/SetServiceType"


class StopFetch(PsegTransientError):
    """Ends a fetch right at the chart stage."""


def test_nj_selects_electric() -> None:
    client = PsegClient(portal_cookies="MM_SID=abc")
    assert getattr(client, "service_type", None) == SERVICE_TYPE_ELECTRIC


def test_nj_with_trailing_slash_selects_electric() -> None:
    client = PsegClient(portal_cookies="MM_SID=abc", portal_url=f"{PORTAL_URL_NJ}/")
    assert getattr(client, "service_type", None) == SERVICE_TYPE_ELECTRIC


def test_long_island_is_left_alone() -> None:
    client = PsegClient(portal_cookies="MM_SID=abc", portal_url=PORTAL_URL_LI)
    assert getattr(client, "service_type", None) is None


@pytest.mark.parametrize("fetch_name", ["fetch_energy_data", "fetch_history_range"])
def test_both_fetches_select_service_after_token_before_chart(fetch_name: str) -> None:
    client = PsegClient(portal_cookies="MM_SID=abc")
    calls: list[tuple[str, str, dict]] = []

    def mock_token():
        calls.append(("token", "", {}))
        return "mock_token"

    def mock_get(url: str, **kwargs):
        calls.append(("get", url, kwargs))
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"Location": f"{PORTAL_URL_NJ}/Dashboard"}
        return resp

    def mock_chart_json(*args, **kwargs):
        calls.append(("chart_json", "", {}))
        raise StopFetch

    def mock_post(url: str, **kwargs):
        calls.append(("post", url, kwargs))
        raise StopFetch

    with (
        patch.object(client, "_get_verification_token", side_effect=mock_token),
        patch.object(client.session, "get", side_effect=mock_get),
        patch.object(client, "_fetch_chart_json", side_effect=mock_chart_json),
        patch.object(client.session, "post", side_effect=mock_post),
    ):
        try:
            if fetch_name == "fetch_history_range":
                client.fetch_history_range("2026-10-01", "2026-10-31")
            else:
                client.fetch_energy_data()
        except StopFetch:
            pass

    assert len(calls) == 3
    assert calls[0][0] == "token"
    assert calls[1][0] == "get"
    assert calls[1][1] == f"{PORTAL_URL_NJ}{SERVICE_TYPE_URL}"
    assert calls[1][2]["params"] == {"ServiceType": SERVICE_TYPE_ELECTRIC}
    assert calls[1][2]["allow_redirects"] is False
    assert calls[2][0] in ("chart_json", "post")


@pytest.mark.parametrize("fetch_name", ["fetch_energy_data", "fetch_history_range"])
def test_long_island_never_calls_set_service_type(fetch_name: str) -> None:
    client = PsegClient(portal_cookies="MM_SID=abc", portal_url=PORTAL_URL_LI)
    assert client.service_type is None
    calls: list[str] = []

    def mock_token():
        calls.append("token")
        return "mock_token"

    def mock_get(url: str, **kwargs):
        calls.append(f"get:{url}")
        resp = MagicMock()
        resp.status_code = 200
        return resp

    def mock_chart_json(*args, **kwargs):
        calls.append("chart")
        raise StopFetch

    def mock_post(url: str, **kwargs):
        calls.append("chart")
        raise StopFetch

    with (
        patch.object(client, "_get_verification_token", side_effect=mock_token),
        patch.object(client.session, "get", side_effect=mock_get),
        patch.object(client, "_fetch_chart_json", side_effect=mock_chart_json),
        patch.object(client.session, "post", side_effect=mock_post),
    ):
        try:
            if fetch_name == "fetch_history_range":
                client.fetch_history_range("2026-10-01", "2026-10-31")
            else:
                client.fetch_energy_data()
        except StopFetch:
            pass

    assert calls == ["token", "chart"]


def _selection_reply(client: PsegClient, status: int, location: str | None = None):
    """A SetServiceType reply that also tries to plant a cookie in the jar."""

    def mock_get(url: str, **kwargs):
        client.session.cookies.set("unwanted", "bad", domain="mysmartenergy.nj.pseg.com", path="/")
        resp = MagicMock()
        resp.status_code = status
        resp.headers = {"Location": location} if location is not None else {}
        return resp

    return mock_get


UNCONFIRMED_REPLIES = [
    pytest.param(404, None, id="http-404"),
    pytest.param(503, None, id="http-503"),
    pytest.param(302, "https://mysmartenergy.nj.pseg.com/signin", id="sign-in"),
    pytest.param(302, "/Maintenance", id="maintenance"),
    pytest.param(302, "Login", id="relative-login"),
    pytest.param(302, "https://evil.example/Dashboard", id="other-host"),
]


@pytest.mark.parametrize("fetch_name", ["fetch_energy_data", "fetch_history_range"])
@pytest.mark.parametrize("known_meter", [False, True], ids=["first-setup", "known-meter"])
@pytest.mark.parametrize(("status", "location"), UNCONFIRMED_REPLIES)
def test_unconfirmed_selection_stops_before_chart(
    status: int, location: str | None, known_meter: bool, fetch_name: str
) -> None:
    client = PsegClient(portal_cookies="MM_SID=abc")
    if known_meter:
        client.set_expected_meter_ids(["12345678"])
    client.session.cookies.set("initial", "valid", domain="mysmartenergy.nj.pseg.com", path="/")

    with (
        patch.object(client, "_get_verification_token", return_value="mock_token"),
        patch.object(client.session, "get", side_effect=_selection_reply(client, status, location)),
        patch.object(client, "_fetch_chart_json") as mock_chart,
        patch.object(client.session, "post") as mock_post,
    ):
        with pytest.raises(PsegTransientError, match="did not select the electric service"):
            if fetch_name == "fetch_history_range":
                client.fetch_history_range("2026-10-01", "2026-10-31")
            else:
                client.fetch_energy_data()

    mock_chart.assert_not_called()
    mock_post.assert_not_called()
    assert client.session.cookies.get("unwanted") is None
    assert client.session.cookies.get("initial") == "valid"


@pytest.mark.parametrize(
    "location",
    ["https://mysmartenergy.nj.pseg.com/Dashboard", "/Dashboard", "/dashboard/"],
)
def test_dashboard_redirect_confirms_selection_without_known_meter(location: str) -> None:
    client = PsegClient(portal_cookies="MM_SID=abc")

    with (
        patch.object(client, "_get_verification_token", return_value="mock_token"),
        patch.object(client.session, "get", side_effect=_selection_reply(client, 302, location)),
        patch.object(client, "_fetch_chart_json", side_effect=StopFetch) as mock_chart,
    ):
        with pytest.raises(StopFetch):
            client.fetch_energy_data()

    mock_chart.assert_called_once()
    # A confirmed selection keeps the jar the portal sent.
    assert client.session.cookies.get("unwanted") == "bad"


def test_renewal_identity_proof_selects_electric_before_its_chart() -> None:
    client = PsegClient(portal_cookies="MM_SID=abc")
    client.set_expected_meter_ids(["12345678"])
    calls: list[str] = []

    def mock_get(url: str, **kwargs):
        calls.append(url)
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"Location": f"{PORTAL_URL_NJ}/Dashboard"}
        return resp

    def mock_chart(*args, **kwargs):
        calls.append("chart")
        raise StopFetch

    dashboard = MagicMock()
    dashboard.text = '<input name="__RequestVerificationToken" value="tok">'
    with (
        patch.object(client.session, "get", side_effect=mock_get),
        patch.object(client, "_fetch_chart_json", side_effect=mock_chart),
    ):
        with pytest.raises(StopFetch):
            client._confirm_meter_identity(dashboard)

    assert calls == [f"{PORTAL_URL_NJ}{SERVICE_TYPE_URL}", "chart"]


@pytest.mark.parametrize("error_cls", [requests.ConnectionError, requests.Timeout])
def test_network_error_raises_transient_error(error_cls: type[Exception]) -> None:
    client = PsegClient(portal_cookies="MM_SID=abc")
    client.session.cookies.set("initial", "valid", domain="mysmartenergy.nj.pseg.com", path="/")

    def mock_get(url: str, **kwargs):
        client.session.cookies.set("unwanted", "bad", domain="mysmartenergy.nj.pseg.com", path="/")
        raise error_cls("down")

    with (
        patch.object(client, "_get_verification_token", return_value="mock_token"),
        patch.object(client.session, "get", side_effect=mock_get),
        patch.object(client, "_fetch_chart_json") as mock_chart,
    ):
        with pytest.raises(PsegTransientError):
            client.fetch_energy_data()

    mock_chart.assert_not_called()
    assert client.session.cookies.get("unwanted") is None
    assert client.session.cookies.get("initial") == "valid"
