"""Tests for selecting the electric service before fetching usage."""

import logging
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


def test_rejected_selection_logs_warning_and_fetch_continues(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = PsegClient(portal_cookies="MM_SID=abc")
    client.session.cookies.set("initial", "valid", domain="mysmartenergy.nj.pseg.com", path="/")

    def mock_get(url: str, **kwargs):
        client.session.cookies.set("unwanted", "bad", domain="mysmartenergy.nj.pseg.com", path="/")
        resp = MagicMock()
        resp.status_code = 404
        return resp

    with (
        patch.object(client, "_get_verification_token", return_value="mock_token"),
        patch.object(client.session, "get", side_effect=mock_get),
        patch.object(client, "_fetch_chart_json", side_effect=StopFetch) as mock_chart,
        caplog.at_level(logging.WARNING),
    ):
        with pytest.raises(StopFetch):
            client.fetch_energy_data()

    mock_chart.assert_called_once()
    assert "MyMeter did not accept service type 1 (HTTP 404)" in caplog.text
    assert client.session.cookies.get("unwanted") is None
    assert client.session.cookies.get("initial") == "valid"


def test_redirect_to_signin_logs_warning_and_fetch_continues(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = PsegClient(portal_cookies="MM_SID=abc")
    client.session.cookies.set("initial", "valid", domain="mysmartenergy.nj.pseg.com", path="/")

    def mock_get(url: str, **kwargs):
        client.session.cookies.set("unwanted", "bad", domain="mysmartenergy.nj.pseg.com", path="/")
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"Location": "https://mysmartenergy.nj.pseg.com/signin"}
        return resp

    with (
        patch.object(client, "_get_verification_token", return_value="mock_token"),
        patch.object(client.session, "get", side_effect=mock_get),
        patch.object(client, "_fetch_chart_json", side_effect=StopFetch) as mock_chart,
        caplog.at_level(logging.WARNING),
    ):
        with pytest.raises(StopFetch):
            client.fetch_energy_data()

    mock_chart.assert_called_once()
    assert "MyMeter redirected service type selection to sign-in" in caplog.text
    assert client.session.cookies.get("unwanted") is None
    assert client.session.cookies.get("initial") == "valid"


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
