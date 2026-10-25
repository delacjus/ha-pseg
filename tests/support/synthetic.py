"""Synthetic data, payload, and cookie generators for systemic testing.

Provides completely invented synthetic identifiers, meters, payloads, and cookies.
No real credentials, account identifiers, meter numbers, or secrets are ever used.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from custom_components.pseg.const import PORTAL_BASE_URL

_SYNTH_COUNTER = 0


def synth_id(prefix: str = "SYNTH") -> str:
    """Generate a unique deterministic synthetic identifier."""
    global _SYNTH_COUNTER
    _SYNTH_COUNTER += 1
    digest = hashlib.sha256(f"{prefix}_{_SYNTH_COUNTER}_{time.time_ns()}".encode()).hexdigest()[:12]
    return f"{prefix}_{digest}"


def build_synthetic_cookies(
    kind: str = "sid",
    value: str | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Generate synthetic cookies according to cookie kind."""
    jar: dict[str, str] = {}
    kind_lower = kind.lower()
    if kind_lower == "none":
        return dict(extra or {})

    if kind_lower in ("sid", "cookie_sid"):
        sid_val = value or synth_id("SYNTH_SID")
        jar["MM_SID"] = sid_val
        jar["idx"] = synth_id("SYNTH_IDX")
        jar["sid"] = synth_id("SYNTH_OKTASID")
    elif kind_lower in ("remember_me", "cookie_remember_me"):
        rm_val = value or synth_id("SYNTH_RM")
        jar["MM_RememberMe"] = rm_val
    elif kind_lower in ("aux", "cookie_aux"):
        aux_val = value or synth_id("SYNTH_AUX")
        jar["portal_aux_pref"] = aux_val
        jar["cf_clearance"] = synth_id("SYNTH_CF")
    else:
        jar[f"SYNTH_COOKIE_{kind}"] = value or synth_id("SYNTH_VAL")

    if extra:
        jar.update(extra)
    return jar


def build_synthetic_meter_point(
    x_timestamp_ms: int = 1729396800000,
    kwh: float = 24.5,
    start_str: str = "10/20/2026",
    end_str: str = "10/20/2026",
) -> dict[str, Any]:
    """Create a single synthetic chart data point conforming to the portal contract."""
    return {
        "x": x_timestamp_ms,
        "y": float(kwh),
        "hs": {
            "start": str(start_str),
            "end": str(end_str),
        },
    }


def build_synthetic_daily_chart(
    meter_id: str = "SYNTH_METER_001",
    kwh: float = 24.5,
    date_str: str = "10/20/2026",
    service_type: str = "RS",
    timestamp_ms: int = 1729396800000,
) -> dict[str, Any]:
    """Create a synthetic DAILY ChartData payload dictionary."""
    return {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{meter_id} ({service_type})",
                    "data": [
                        build_synthetic_meter_point(
                            x_timestamp_ms=timestamp_ms,
                            kwh=kwh,
                            start_str=date_str,
                            end_str=date_str,
                        )
                    ],
                }
            ]
        }
    }


def build_synthetic_hourly_chart(
    meter_id: str = "SYNTH_METER_001",
    date_str: str = "10/20/2026",
    num_hours: int = 24,
    kwh_per_hour: float = 1.0,
    service_type: str = "RS",
    base_timestamp_ms: int = 1729396800000,
) -> dict[str, Any]:
    """Create a synthetic HOURLY ChartData payload dictionary."""
    points: list[dict[str, Any]] = []
    for h in range(num_hours):
        hour_start = f"{date_str} {h:02d}:00"
        hour_end = f"{date_str} {h + 1:02d}:00"
        ts = base_timestamp_ms + (h * 3600 * 1000)
        points.append(
            build_synthetic_meter_point(
                x_timestamp_ms=ts,
                kwh=kwh_per_hour,
                start_str=hour_start,
                end_str=hour_end,
            )
        )

    return {
        "Data": {
            "series": [
                {
                    "name": f"Meter #{meter_id} ({service_type})",
                    "data": points,
                }
            ]
        }
    }


def build_synthetic_dashboard_html(
    token: str = "SYNTH_TOKEN_DEFAULT",
    logged_in: bool = True,
    title: str = "Dashboard",
) -> str:
    """Create synthetic Dashboard HTML markup."""
    if not logged_in:
        return '<html><head><title>Public</title></head><body><a href="/Saml/okta-prod/SignIn">Sign in</a></body></html>'

    return (
        f"<html><head><title>{title}</title></head><body>"
        "<h1>Welcome to PSE&G MyMeter</h1>"
        f'<input name="__RequestVerificationToken" value="{token}"/>'
        '<a href="/Account/LogOff">Log out</a>'
        '<div id="portal_user_banner">User SYNTH_USER</div>'
        "</body></html>"
    )


def build_synthetic_login_form(token: str = "SYNTH_TOKEN_LOGIN") -> str:
    """Create synthetic portal login page HTML markup."""
    return (
        "<html><head><title>Sign in to MyMeter</title></head><body>"
        f'<form action="{PORTAL_BASE_URL}/Home/Login" method="post">'
        f'<input name="__RequestVerificationToken" value="{token}"/>'
        '<input name="Email" type="email"/>'
        '<input name="Password" type="password"/>'
        "</form></body></html>"
    )


def build_synthetic_saml_acs(success: bool = True) -> str:
    """Create synthetic SAML ACS autopost form or error markup."""
    if not success:
        return "<html><body><h1>SAML Authentication Failed</h1></body></html>"
    return (
        "<html><body>"
        f'<form id="appForm" method="POST" action="{PORTAL_BASE_URL}/Saml/okta-prod/Acs">'
        '<input type="hidden" name="SAMLResponse" value="SYNTH_SAML_RESPONSE_DATA"/>'
        '<input type="hidden" name="RelayState" value="SYNTH_RELAY_STATE"/>'
        "</form></body></html>"
    )


def build_synthetic_maintenance_html() -> str:
    """Create synthetic maintenance page response."""
    return (
        "<html><head><title>Scheduled Maintenance</title></head><body>"
        "<h1>PSE&G MyMeter Maintenance</h1>"
        "<p>The system is currently undergoing scheduled maintenance. Please check back later.</p>"
        "</body></html>"
    )


def build_synthetic_missing_token_html() -> str:
    """Create synthetic Dashboard response missing the verification token."""
    return (
        "<html><head><title>Dashboard</title></head><body>"
        "<h1>Welcome to PSE&G MyMeter</h1>"
        "<p>No verification token here</p>"
        "</body></html>"
    )


def build_synthetic_unrelated_html() -> str:
    """Create synthetic unrelated 3rd party response."""
    return "<html><body><h1>Default Web Page</h1><p>Under Construction</p></body></html>"


def build_synthetic_all_invalid_chart() -> dict[str, Any]:
    """Create a synthetic chart payload with completely invalid entries."""
    return {
        "Data": {
            "series": [
                {
                    "name": "Invalid Meter",
                    "data": [
                        {"x": "not_an_int", "y": None, "hs": {"start": "invalid_date"}},
                        {"x": None, "y": "NaN", "hs": None},
                    ],
                }
            ]
        }
    }


def build_synthetic_root_array() -> list[Any]:
    """Create synthetic root-array JSON payload."""
    return [{"status": "unexpected_root_array", "code": 200}]


def build_synthetic_root_string() -> str:
    """Create synthetic root-string JSON payload."""
    return json.dumps("unexpected_bare_string_response")


def build_synthetic_root_null() -> str:
    """Create synthetic root-null JSON payload."""
    return json.dumps(None)


def build_synthetic_root_number() -> str:
    """Create synthetic root-number JSON payload."""
    return json.dumps(12345678)


def build_synthetic_truncated_json() -> str:
    """Create synthetic truncated unparseable JSON string."""
    return '{"Data": {"series": [{"name": "Truncated", "data": '


def build_synthetic_empty_payload() -> str:
    """Create synthetic empty payload string."""
    return ""


def build_synthetic_captcha_html() -> str:
    """Generate synthetic HTML for a CAPTCHA challenge on login."""
    return (
        "<!DOCTYPE html><html><body>"
        "<div class='error-msg'>Please provide a valid login captcha.</div>"
        "<form action='/Home/Login' method='post'>"
        "<input name='__RequestVerificationToken' value='SYNTH_TOKEN_CAPTCHA' />"
        "<input name='RecaptchaOnLogin' value='True' />"
        "</form></body></html>"
    )


def build_synthetic_security_step_html() -> str:
    """Generate synthetic HTML for a security step challenge."""
    return (
        "<!DOCTYPE html><html><body>"
        "<div class='security-challenge'>Additional security verification required</div>"
        "<form action='/Security/Verify' method='post'>"
        "<input name='__RequestVerificationToken' value='SYNTH_TOKEN_SECURITY' />"
        "</form></body></html>"
    )
