"""Constants for the PSE&G Energy integration."""

from __future__ import annotations

DOMAIN = "pseg"

# Device name; with has_entity_name entities become sensor.pseg_<translation name>.
DEVICE_NAME = "PSEG"

CONF_OKTA_COOKIES = "okta_cookies"
CONF_PORTAL_COOKIES = "portal_cookies"
CONF_COOKIE = "cookie"
CONF_PRICE_PER_KWH = "price_per_kwh"
CONF_METER_ID = "meter_id"
CONF_KNOWN_METER_IDS = "known_meter_ids"
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
# Placeholder the client reports when the chart has no meter series.
DEFAULT_METER_NAME = "PSE&G Electric Meter"
DEFAULT_SCAN_INTERVAL_HOURS = 4
# Okta mode: must stay below PSE&G's Okta idle timeout (observed ~30 min, 2026-10-21).
KEEPALIVE_INTERVAL_MINUTES = 10
# Local (portal-only) mode: MM_SID lapses on an idle timer of ~10 min (observed live
# 2026-10-22). A GET-only touch well under that keeps the session warm without any
# credential POST, so renewal can stay on the poll path.
LOCAL_KEEPALIVE_INTERVAL_MINUTES = 3

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
AUTH_REASONS = frozenset({
    AUTH_REASON_PORTAL_SESSION_EXPIRED,
    AUTH_REASON_CAPTCHA_REQUIRED,
    AUTH_REASON_REMEMBER_ME_REJECTED,
    AUTH_REASON_SECURITY_STEP,
    AUTH_REASON_OKTA_SESSION_EXPIRED,
})

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
