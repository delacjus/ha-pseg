"""Constants for the PSE&G Energy integration."""

from __future__ import annotations

import logging
import math

_LOGGER = logging.getLogger(__name__)

DOMAIN = "pseg"

# Device name; with has_entity_name entities become sensor.pseg_<translation name>.
DEVICE_NAME = "PSEG"

CONF_OKTA_COOKIES = "okta_cookies"
CONF_PORTAL_COOKIES = "portal_cookies"
CONF_COOKIE = "cookie"
CONF_PRICE_PER_KWH = "price_per_kwh"
CONF_METER_ID = "meter_id"
CONF_KNOWN_METER_IDS = "known_meter_ids"
# Kill switch for every statistics import (automatic poll, deferred startup import and
# the manual backfill action). Authentication and keepalive are never affected.
CONF_STATISTICS_IMPORT_ENABLED = "statistics_import_enabled"
DEFAULT_STATISTICS_IMPORT_ENABLED = True
# MyMeter local login (email/password); HA signs in itself when the session lapses.
CONF_MYMETER_EMAIL = "mymeter_email"
CONF_MYMETER_PASSWORD = "mymeter_password"
# MyMeter local login 'Remember Me' cookie (~1 year), the long-lived renewal path.
REMEMBER_ME_COOKIE = "MM_RememberMe"
# Cookies that carry the signed-in session itself. A persisted jar that loses one
# of these is a half-empty jar from a failed renewal, not a rotated one.
SESSION_COOKIE_NAMES = frozenset({"MM_SID", "idx", "sid"})
# Human CAPTCHA hand-off (config flow only): one-use proof, never persisted.
CONF_CAPTCHA_RESPONSE = "captcha_response"
CONF_CAPTCHA_CANCEL = "captcha_cancel"
# How long a prepared CAPTCHA sign-in (client, cookie jar, antiforgery state) stays
# pending. This is NOT the proof's lifetime: Google/PSE&G give a reCAPTCHA response
# about two minutes, and Home Assistant cannot see when the browser captured it, so
# the provider stays the authority on freshness. HA only bounds its own pending state.
CAPTCHA_ATTEMPT_TTL_SECONDS = 600

DEFAULT_PRICE_PER_KWH = 0.247
# MyMeter /Dashboard/Chart UsageInterval values (live contract, 2026-10-23).
USAGE_INTERVAL_HOURLY = "5"
USAGE_INTERVAL_DAILY = "6"
# Cumulative sums and hourly cost states keep six decimals: rounding each hour to
# cents accumulates a visible error over a day (24 x $0.005 worst case).
STATISTICS_PRECISION = 6
# Placeholder the client reports when the chart has no meter series.
DEFAULT_METER_NAME = "PSE&G Electric Meter"
DEFAULT_SCAN_INTERVAL_HOURS = 4
# Okta mode: must stay below the observed Okta idle interval (~30 min, 2026-10-21).
# The vendor's actual timeout is not documented.
KEEPALIVE_INTERVAL_MINUTES = 10
# Local (portal-only) mode: one observed session lapse happened after ~9 minutes
# without an accepted request (2026-10-23), but the server's real rule is unknown.
# A credential-free GET every 3 minutes is a probe, not a vendor TTL contract.
LOCAL_KEEPALIVE_INTERVAL_MINUTES = 3

# Non-secret bookkeeping for bounded Remember Me renewals, stored in entry.data next
# to the cookie jar so an options reload cannot reset the vendor-load budget. Never
# holds a cookie value, fingerprint or credential.
CONF_RENEWAL_ADMISSION = "renewal_admission"
# Product limit, not a vendor contract: at most two cookie-renewal sequences per
# verified Remember Me cookie generation, and at least 15 minutes between any two
# sequences (including across generations).
LOCAL_RENEWAL_MIN_INTERVAL_SECONDS = 15 * 60
LOCAL_RENEWAL_MAX_SEQUENCES = 2

# Typed authentication failure reasons (client.auth_reason, status sensor attribute).
# A reason is set wherever authentication fails, so local MyMeter failures are never
# reported as an Okta session expiry.
AUTH_REASON_PORTAL_SESSION_EXPIRED = "portal_session_expired"
AUTH_REASON_CAPTCHA_REQUIRED = "captcha_required"
# A saved local renewal credential was refused: the Remember Me cookie or the saved
# MyMeter email/password.
AUTH_REASON_REMEMBER_ME_REJECTED = "remember_me_rejected"
AUTH_REASON_SECURITY_STEP = "security_step"
AUTH_REASON_OKTA_SESSION_EXPIRED = "okta_session_expired"
AUTH_REASONS = frozenset(
    {
        AUTH_REASON_PORTAL_SESSION_EXPIRED,
        AUTH_REASON_CAPTCHA_REQUIRED,
        AUTH_REASON_REMEMBER_ME_REJECTED,
        AUTH_REASON_SECURITY_STEP,
        AUTH_REASON_OKTA_SESSION_EXPIRED,
    }
)

PORTAL_HOST = "mysmartenergy.nj.pseg.com"
OKTA_HOST = "id.myaccount.pseg.com"
ALLOWED_HOSTS = {PORTAL_HOST, OKTA_HOST}

PORTAL_BASE_URL = f"https://{PORTAL_HOST}"

ATTR_METER = "meter"
ATTR_LATEST_DATE = "latest_date"
ATTR_PREVIOUS_DATE = "previous_date"
ATTR_PREVIOUS_KWH = "previous_kwh"
ATTR_PREVIOUS_COST = "previous_cost"
ATTR_LATEST_COST = "latest_cost"
ATTR_HISTORY_14D = "history_14d"
ATTR_TEMPERATURE_HIGH = "temperature_high"
ATTR_TEMPERATURE_LOW = "temperature_low"
ATTR_TEMPERATURE_AVG = "temperature_avg"

ATTR_SESSION_ESTABLISHED_AT = "session_established_at"
ATTR_LAST_SSO_RENEWAL = "last_sso_renewal"
ATTR_SSO_RENEWALS = "sso_renewals"
ATTR_LAST_KEEPALIVE = "last_keepalive"
ATTR_OKTA_SESSION_EXPIRED_AT = "okta_session_expired_at"
ATTR_AUTH_REASON = "auth_reason"
# Seconds between the last confirmed portal request and the authentication failure.
ATTR_AUTH_IDLE_GAP = "idle_gap_seconds"

# Real-cost evidence mode control and parameters (v1.7.0 evidence only)
COST_MODE_OFF = "off"
COST_MODE_EVIDENCE = "evidence"
COST_MODE_IMPORT = "import"
COST_MODES = frozenset({COST_MODE_OFF, COST_MODE_EVIDENCE, COST_MODE_IMPORT})
DEFAULT_COST_MODE = COST_MODE_OFF

# MyMeter /Dashboard/Chart UsageType
USAGE_TYPE_CONSUMPTION = "1"
USAGE_TYPE_COST = "2"

SERVICE_SET_COST_MODE = "set_cost_mode"

# Fixed reasons a stored price_per_kwh option can be unusable. The reason is logged;
# the stored value itself never is (it is user data and may change between releases).
PRICE_REASON_NOT_A_NUMBER = "not a number"
PRICE_REASON_NOT_FINITE = "not a finite number"
PRICE_REASON_NEGATIVE = "negative"


def classify_price_per_kwh(raw: object) -> tuple[float | None, str | None]:
    """Apply the one validity rule for the price-per-kWh option.

    A usable rate is a finite, non-negative number; the numeric string the options
    form accepts is coerced exactly like it. Returns ``(rate, None)`` when usable and
    ``(None, reason)`` otherwise. Both the options flow (new submissions) and the
    load paths (previously saved options) call this, so they cannot disagree.
    """
    if isinstance(raw, bool):
        return None, PRICE_REASON_NOT_A_NUMBER
    try:
        rate = float(raw)  # type: ignore[arg-type]
    except TypeError, ValueError, OverflowError:
        return None, PRICE_REASON_NOT_A_NUMBER
    if not math.isfinite(rate):
        return None, PRICE_REASON_NOT_FINITE
    if rate < 0:
        return None, PRICE_REASON_NEGATIVE
    return rate, None


def parse_price_per_kwh(raw: object) -> float | None:
    """Return the usable rate, or None when the shared rule rejects it."""
    rate, _reason = classify_price_per_kwh(raw)
    return rate


def sanitized_price_per_kwh(raw: object, *, warn: bool = True) -> float:
    """Turn a stored price_per_kwh value into a rate that is safe to use.

    Finite and non-negative values (including 0) are kept exactly as-is. Anything
    else falls back to DEFAULT_PRICE_PER_KWH, because a negative, non-finite or
    non-numeric rate would otherwise produce negative or NaN costs and can drop
    accumulated statistics rows. The warning names only the reason, never the value.
    The stored option is never rewritten here: the options flow stays its only writer.
    """
    rate, reason = classify_price_per_kwh(raw)
    if rate is not None:
        return rate
    if warn:
        _LOGGER.warning(
            "Ignoring the saved price per kWh option because it is %s; "
            "estimating costs with the default rate instead",
            reason,
        )
    return DEFAULT_PRICE_PER_KWH
