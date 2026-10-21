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

DEFAULT_PRICE_PER_KWH = 0.247
# Placeholder the client reports when the chart has no meter series.
DEFAULT_METER_NAME = "PSE&G Electric Meter"
DEFAULT_SCAN_INTERVAL_HOURS = 4
KEEPALIVE_INTERVAL_MINUTES = 30

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
