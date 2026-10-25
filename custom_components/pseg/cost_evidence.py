"""Bounded, isolated cost evidence sampler and durable budget store for PSE&G real cost.

This module implements RC-02:
- Bounded, isolated cost sampler inside the locked client sequence.
- Uses a short-lived AllowlistedSession with RejectingCookieJar (rejects response cookies).
- allow_redirects=False (any 30x HTTP response is an immediate evidence rejection).
- Two-dispatch sequence: POST /Dashboard/Chart (UsageType "2") then GET /Dashboard/ChartData.
- 10-second whole-pair deadline including streamed body reading and 1 MiB max bytes.
- Fixed evidence status vocabulary; failures never fail a healthy kWh poll or alter auth metadata.
- Durable auth-free evidence Store managing one reserved sampling permit per entry per NY day.
- Admin control mode (off | evidence, import reserved/refused in v1.7.0).
- Bounded cost_contract_sample diagnostics representation (<=4 series, 1,500 points, 2 slots, 256 KiB).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import copy
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import StrEnum
import gzip
import json
import logging
import math
import time
from typing import Any
import uuid
import zlib
import zoneinfo

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store
import requests
import requests.cookies

from .const import (
    COST_MODE_EVIDENCE,
    COST_MODE_IMPORT,
    COST_MODE_OFF,
    PORTAL_BASE_URL,
    PORTAL_HOST,
    USAGE_INTERVAL_DAILY,
    USAGE_INTERVAL_HOURLY,
    USAGE_TYPE_COST,
)
from .pseg_client import (
    _METER_SERIES,
    AllowlistedSession,
    PsegSecurityError,
    PsegTransientError,
)

_LOGGER = logging.getLogger(__name__)

NY_TZ = zoneinfo.ZoneInfo("America/New_York")

STORAGE_VERSION = 1

MAX_COST_SERIES = 4
MAX_COST_POINTS = 1500
MAX_COST_BYTES = 1024 * 1024  # 1 MiB streamed byte cap
MAX_SERIALIZED_SAMPLE_BYTES = 256 * 1024  # 256 KiB serialized JSON bound
MAX_SAMPLE_SLOTS = 2
COST_PAIR_DEADLINE_SECONDS = 10.0

# Closed vocabulary for reasons (never format server strings or exception text)
REASON_EMPTY_PAYLOAD = "empty_payload"
REASON_PAYLOAD_NOT_DICT = "payload_not_dict"
REASON_MISSING_DATA_BLOCK = "missing_data_block"
REASON_DATA_BLOCK_NOT_DICT = "data_block_not_dict"
REASON_MISSING_SERIES = "missing_series"
REASON_SERIES_NOT_LIST = "series_not_list"
REASON_EMPTY_SERIES = "empty_series"
REASON_UNSUPPORTED_UNIT = "unsupported_unit"
REASON_CURRENCY_UNPROVEN = "currency_unproven"
REASON_SERIES_ITEM_NOT_DICT = "series_item_not_dict"
REASON_METER_NOT_AUTHORITATIVE = "meter_not_authoritative"
REASON_NO_AUTHORITATIVE_METER_SERIES = "no_authoritative_meter_series"
REASON_POINTS_NOT_LIST = "points_not_list"
REASON_POINT_NOT_DICT = "point_not_dict"
REASON_DUPLICATE_POINT = "duplicate_point"
REASON_QUARANTINE_NON_NUMERIC = "quarantine_non_numeric"
REASON_QUARANTINE_NON_FINITE = "quarantine_non_finite"
REASON_QUARANTINE_NEGATIVE = "quarantine_negative"
REASON_INVALID_POINT_X = "invalid_point_x"
REASON_SERIES_COUNT_EXCEEDED = "series_count_exceeded"
REASON_POINT_COUNT_EXCEEDED = "point_count_exceeded"
REASON_STREAM_BYTE_CAP_EXCEEDED = "stream_byte_cap_exceeded"
REASON_TOTAL_SIZE_EXCEEDED = "total_size_exceeded"
REASON_TIMEOUT = "timeout"
REASON_REDIRECT = "redirect"
REASON_LOGIN_PAGE = "login_page_detected"
REASON_HTTP_ERROR = "http_error"
REASON_EMPTY_BODY = "empty_body"
REASON_JSON_DECODE_ERROR = "json_decode_error"
REASON_SERIALIZATION_ERROR = "serialization_error"
REASON_STREAM_READ_ERROR = "stream_read_error"
REASON_SECURITY_GUARD = "security_guard"
REASON_NETWORK_ERROR = "network_error"
REASON_UNEXPECTED_ERROR = "unexpected_error"

_SHARED_STORE_DATA_KEY = "pseg_cost_evidence_shared_data"
_SHARED_STORE_LOCKS_KEY = "pseg_cost_evidence_shared_locks"


class CostEvidenceStatus(StrEnum):
    """Status vocabulary for non-authoritative cost evidence evaluations."""

    OK = "ok"
    MISSING = "missing"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    AUTH_REJECTED = "auth_rejected"
    WRONG_METER = "wrong_meter"
    WRONG_UNIT = "wrong_unit"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TRUNCATED = "truncated"


@dataclass(frozen=True)
class CostPermit:
    """Immutable one-use permit authorizing a single cost chart attempt."""

    permit_id: str
    entry_id: str
    ny_date: str
    usage_interval: str
    start_str: str
    end_str: str
    created_at: str


class RejectingCookieJar(requests.cookies.RequestsCookieJar):
    """Cookie jar that seeds once and rejects all subsequent Set-Cookie updates."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize jar with lock disarmed."""
        super().__init__(*args, **kwargs)
        self._locked: bool = False

    def lock(self) -> None:
        """Lock jar against any further cookie mutation."""
        self._locked = True

    def set_cookie(self, cookie: Any, *args: Any, **kwargs: Any) -> None:
        """Disallow adding/updating cookies once locked."""
        if self._locked:
            return
        super().set_cookie(cookie, *args, **kwargs)

    def extract_cookies(self, response: Any, request: Any) -> None:
        """Disallow extracting Set-Cookie headers from responses once locked."""
        if self._locked:
            return
        super().extract_cookies(response, request)


def _is_valid_store_payload(stored: Any) -> bool:
    """Strict schema validation of the Store payload."""
    if not isinstance(stored, dict):
        return False
    if stored.get("version") != STORAGE_VERSION:
        return False
    mode = stored.get("mode")
    if mode not in (COST_MODE_OFF, COST_MODE_EVIDENCE):
        return False
    last_interval = stored.get("last_interval")
    if last_interval is not None and last_interval not in (
        USAGE_INTERVAL_DAILY,
        USAGE_INTERVAL_HOURLY,
    ):
        return False
    reservations = stored.get("reservations")
    if not isinstance(reservations, dict):
        return False
    for k, v in reservations.items():
        if not isinstance(k, str):
            return False
        try:
            date.fromisoformat(k)
        except ValueError:
            return False
        if not isinstance(v, dict):
            return False
        permit_id = v.get("permit_id")
        if not isinstance(permit_id, str) or not permit_id:
            return False
        interval = v.get("usage_interval")
        if interval not in (USAGE_INTERVAL_DAILY, USAGE_INTERVAL_HOURLY):
            return False
    return True


class CostEvidenceStore:
    """Durable, auth-free Store for cost sampling mode and daily attempt reservations."""

    def __init__(self, hass: HomeAssistant, entry_id: str) -> None:
        """Create the cost evidence store for a single config entry."""
        self._hass = hass
        self._entry_id = entry_id
        self._store = Store(
            hass,
            STORAGE_VERSION,
            f"pseg.cost_evidence.{entry_id}",
            atomic_writes=True,
        )
        self._loaded: bool = False
        self._corrupted: bool = False
        self._data: dict[str, Any] = {
            "version": STORAGE_VERSION,
            "mode": COST_MODE_OFF,
            "reservations": {},
            "last_interval": None,
        }

    async def async_load(self) -> None:
        """Load the store from disk once, failing closed on unknown/corrupt state."""
        shared_data = self._hass.data.setdefault(_SHARED_STORE_DATA_KEY, {})
        if self._entry_id in shared_data:
            self._data = shared_data[self._entry_id]
            self._corrupted = bool(self._data.get("__corrupted__", False))
            self._loaded = True
            return

        if self._loaded:
            return

        try:
            stored = await self._store.async_load()
            if stored is not None:
                if not _is_valid_store_payload(stored):
                    _LOGGER.warning("Cost evidence store payload failed schema validation; corrupt")
                    self._corrupted = True
                    self._data = {"__corrupted__": True}
                else:
                    self._data = stored
        except Exception as err:
            _LOGGER.warning("Failed to load cost evidence store: %s", err)
            self._corrupted = True
            self._data = {"__corrupted__": True}

        if self._corrupted:
            self._data["__corrupted__"] = True

        shared_data[self._entry_id] = self._data
        self._loaded = True

    @property
    def mode(self) -> str:
        """Return the current operator cost mode."""
        if self._corrupted:
            return COST_MODE_OFF
        return str(self._data.get("mode", COST_MODE_OFF))

    async def async_set_mode(self, mode: str) -> None:
        """Update operator cost mode.

        Does not reset budgets, authenticate, refresh, switch Energy, or clear state.
        """
        if mode == COST_MODE_IMPORT:
            raise ValueError("Cost mode 'import' is reserved and refused in v1.7.0")
        if mode not in (COST_MODE_OFF, COST_MODE_EVIDENCE):
            raise ValueError(f"Invalid cost mode '{mode}': expected 'off' or 'evidence'")

        if self._corrupted:
            raise ValueError("Cannot set cost mode on a corrupted store")

        self._data["mode"] = mode
        save_data = {k: v for k, v in self._data.items() if k != "__corrupted__"}
        await self._store.async_save(save_data)

    async def async_reserve_permit(
        self,
        ny_date: date,
        start_str: str,
        end_str: str,
    ) -> CostPermit | None:
        """Durably reserve one due attempt permit for this NY day.

        Survives reload, restart, and manual refresh. Returns None if already
        reserved today, mode is not evidence, or store is corrupt.
        """
        if self._corrupted or self.mode != COST_MODE_EVIDENCE:
            return None

        shared_locks = self._hass.data.setdefault(_SHARED_STORE_LOCKS_KEY, {})
        lock = shared_locks.setdefault(self._entry_id, asyncio.Lock())

        async with lock:
            if self._corrupted or self.mode != COST_MODE_EVIDENCE:
                return None

            reservations: dict[str, Any] = self._data.setdefault("reservations", {})
            ny_date_str = ny_date.isoformat()
            if ny_date_str in reservations:
                # Budget exhausted for today
                return None

            # Alternating daily / hourly / daily schedule
            last_interval = self._data.get("last_interval")
            if last_interval == USAGE_INTERVAL_DAILY:
                interval = USAGE_INTERVAL_HOURLY
            else:
                interval = USAGE_INTERVAL_DAILY

            permit = CostPermit(
                permit_id=uuid.uuid4().hex,
                entry_id=self._entry_id,
                ny_date=ny_date_str,
                usage_interval=interval,
                start_str=start_str,
                end_str=end_str,
                created_at=datetime.now(UTC).isoformat(),
            )

            reservations[ny_date_str] = {
                "permit_id": permit.permit_id,
                "usage_interval": permit.usage_interval,
                "start": start_str,
                "end": end_str,
                "reserved_at": permit.created_at,
            }
            self._data["last_interval"] = interval
            save_data = {k: v for k, v in self._data.items() if k != "__corrupted__"}
            await self._store.async_save(save_data)
            return permit

    def get_readiness_reason(self, ny_date: date) -> str:
        """Return operator readiness status for diagnostics."""
        if self._corrupted:
            return "corrupt_store"
        if self.mode == COST_MODE_OFF:
            return "mode_off"
        reservations = self._data.get("reservations", {})
        if ny_date.isoformat() in reservations:
            return "budget_exhausted_for_today"
        return "ready"


def _is_login_response(resp: requests.Response, body_bytes: bytes) -> bool:
    """Check if response is or redirects to an unauthenticated login page."""
    if resp.status_code in (401, 403):
        return True
    body_str = body_bytes.decode("utf-8", errors="ignore").lower()
    if "sign in" in body_str and (
        "password" in body_str or "mymeter" in body_str or "okta" in body_str
    ):
        return True
    return False


def _set_socket_timeout(resp: requests.Response, timeout: float) -> None:
    """Set timeout on underlying socket if accessible."""
    raw = getattr(resp, "raw", None)
    if raw is None:
        return
    candidates = [
        raw,
        getattr(raw, "_fp", None),
        getattr(getattr(raw, "_fp", None), "fp", None),
        getattr(getattr(raw, "_fp", None), "_sock", None),
        getattr(getattr(getattr(raw, "_fp", None), "fp", None), "raw", None),
        getattr(getattr(getattr(raw, "_fp", None), "fp", None), "_sock", None),
    ]
    for c in candidates:
        if c is not None and hasattr(c, "settimeout"):
            try:
                c.settimeout(max(0.001, timeout))
            except Exception:
                pass


def _stream_response_body(
    resp: requests.Response,
    deadline: float,
    max_bytes: int = MAX_COST_BYTES,
    chunk_size: int = 1024,
    read_timeout_cap: float = 0.5,
) -> tuple[bytes | None, str | None]:
    """Stream response body bounded by deadline and maximum byte cap.

    Enforces deadline during reads by checking time before/after each small read,
    updating socket timeout per read, and returning read_error on stream failures.
    """
    content = bytearray()
    raw = getattr(resp, "raw", None)

    try:
        if raw is not None and hasattr(raw, "read"):
            while True:
                now = time.monotonic()
                if now >= deadline:
                    return None, "timeout"
                remaining = deadline - now
                read_timeout = min(remaining, read_timeout_cap)
                _set_socket_timeout(resp, read_timeout)
                # decode_content=False returns immediately from raw socket/stream without blocking
                chunk = raw.read(chunk_size, decode_content=False)
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > max_bytes:
                    return None, "byte_cap_exceeded"
                if time.monotonic() >= deadline:
                    return None, "timeout"
        elif hasattr(resp, "_content") and resp._content is not None:
            content.extend(resp._content)
            if len(content) > max_bytes:
                return None, "byte_cap_exceeded"
        else:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if time.monotonic() >= deadline:
                    return None, "timeout"
                if chunk:
                    content.extend(chunk)
                    if len(content) > max_bytes:
                        return None, "byte_cap_exceeded"
                if time.monotonic() >= deadline:
                    return None, "timeout"
    except requests.Timeout, TimeoutError:
        return None, "timeout"
    except Exception as err:
        return None, f"read_error: {err}"

    data = bytes(content)
    encoding = ""
    if hasattr(resp, "headers") and resp.headers:
        encoding = (resp.headers.get("Content-Encoding") or "").lower()
    if not encoding and raw is not None and hasattr(raw, "headers") and raw.headers:
        encoding = (raw.headers.get("Content-Encoding") or "").lower()

    if "gzip" in encoding:
        try:
            data = gzip.decompress(data)
        except Exception as dec_err:
            return None, f"read_error: {dec_err}"
    elif "deflate" in encoding:
        try:
            data = zlib.decompress(data)
        except Exception as dec_err:
            return None, f"read_error: {dec_err}"

    return data, None


_DATE_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
    "%m/%d/%Y",
)


def _parse_and_format_date(val: Any) -> str | None:
    """Parse date/datetime string and re-emit strictly in canonical format."""
    if not isinstance(val, str) or not val.strip():
        return None
    s = val.strip()
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if fmt in ("%Y-%m-%d", "%m/%d/%Y"):
                return dt.strftime("%Y-%m-%d")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(s)
        if dt.time() == datetime.min.time() and "T" not in s and " " not in s:
            return dt.strftime("%Y-%m-%d")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass
    return None


def validate_and_sanitize_cost_payload(
    payload: Any,
    authoritative_meters: set[str] | list[str],
    meter_placeholders: dict[str, str],
    permit: CostPermit,
    paired_kwh_anchors: dict[str, Any] | None = None,
) -> tuple[CostEvidenceStatus, dict[str, Any], bool]:
    """Validate raw ChartData payload and construct privacy-bounded diagnostics sample.

    Enforces authoritative meter identity matching, USD currency proof, zero validity,
    point quarantines, strict numeric/date parsing, and <=4 series / 1,500 points / 256 KiB bounds.
    Returns (status, sample, promotable).
    """
    if payload is None or payload == {}:
        return (
            CostEvidenceStatus.MISSING,
            {"status": CostEvidenceStatus.MISSING.value, "reason": REASON_EMPTY_PAYLOAD},
            False,
        )

    if not isinstance(payload, dict):
        return (
            CostEvidenceStatus.MALFORMED,
            {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_PAYLOAD_NOT_DICT},
            False,
        )

    data_block = payload.get("Data")
    if data_block is None:
        return (
            CostEvidenceStatus.MISSING,
            {"status": CostEvidenceStatus.MISSING.value, "reason": REASON_MISSING_DATA_BLOCK},
            False,
        )
    if not isinstance(data_block, dict):
        return (
            CostEvidenceStatus.MALFORMED,
            {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_DATA_BLOCK_NOT_DICT},
            False,
        )

    raw_series = data_block.get("series")
    if raw_series is None:
        return (
            CostEvidenceStatus.MISSING,
            {"status": CostEvidenceStatus.MISSING.value, "reason": REASON_MISSING_SERIES},
            False,
        )
    if not isinstance(raw_series, list):
        return (
            CostEvidenceStatus.MALFORMED,
            {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_SERIES_NOT_LIST},
            False,
        )
    if len(raw_series) == 0:
        return (
            CostEvidenceStatus.MISSING,
            {"status": CostEvidenceStatus.MISSING.value, "reason": REASON_EMPTY_SERIES},
            False,
        )

    # Unit / Currency check: USD must be PROVEN from closed set ("USD", "$")
    proven_usd = False
    for unit_key in ("unit", "unitOfMeasure", "currency", "yAxisTitle"):
        val = data_block.get(unit_key)
        if val is None or not str(val).strip():
            continue
        if str(val).strip().upper() not in ("USD", "$"):
            return (
                CostEvidenceStatus.WRONG_UNIT,
                {
                    "status": CostEvidenceStatus.WRONG_UNIT.value,
                    "reason": REASON_UNSUPPORTED_UNIT,
                },
                False,
            )
        proven_usd = True
    if not proven_usd:
        return (
            CostEvidenceStatus.WRONG_UNIT,
            {"status": CostEvidenceStatus.WRONG_UNIT.value, "reason": REASON_CURRENCY_UNPROVEN},
            False,
        )

    auth_set = {str(m) for m in authoritative_meters if m}
    matched_series: list[dict[str, Any]] = []
    total_points = 0
    seen_keys: set[tuple[str, int]] = set()
    dropped_count = 0

    for series_item in raw_series:
        if not isinstance(series_item, dict):
            return (
                CostEvidenceStatus.MALFORMED,
                {
                    "status": CostEvidenceStatus.MALFORMED.value,
                    "reason": REASON_SERIES_ITEM_NOT_DICT,
                },
                False,
            )

        name = str(series_item.get("name") or "")
        match = _METER_SERIES.match(name)
        if not match:
            # Skip non-meter telemetry, drop and count
            dropped_count += 1
            continue

        meter_id = match.group(1)
        if meter_id not in auth_set:
            return (
                CostEvidenceStatus.WRONG_METER,
                {
                    "status": CostEvidenceStatus.WRONG_METER.value,
                    "reason": REASON_METER_NOT_AUTHORITATIVE,
                },
                False,
            )

        if meter_id not in meter_placeholders:
            placeholder = str(len(meter_placeholders) + 1)
            meter_placeholders[meter_id] = placeholder
        else:
            placeholder = meter_placeholders[meter_id]

        raw_points = series_item.get("data")
        if not isinstance(raw_points, list):
            return (
                CostEvidenceStatus.MALFORMED,
                {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_POINTS_NOT_LIST},
                False,
            )

        total_points += len(raw_points)
        seen_x: set[int] = set()
        sanitized_points: list[dict[str, Any]] = []

        for pt in raw_points:
            if not isinstance(pt, dict):
                return (
                    CostEvidenceStatus.MALFORMED,
                    {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_POINT_NOT_DICT},
                    False,
                )

            # Strict numeric parser for x
            raw_x = pt.get("x")
            if isinstance(raw_x, bool) or raw_x is None:
                return (
                    CostEvidenceStatus.MALFORMED,
                    {
                        "status": CostEvidenceStatus.MALFORMED.value,
                        "reason": REASON_INVALID_POINT_X,
                    },
                    False,
                )

            num_x: int
            if isinstance(raw_x, int):
                num_x = raw_x
            elif isinstance(raw_x, float):
                if not math.isfinite(raw_x) or not raw_x.is_integer():
                    return (
                        CostEvidenceStatus.MALFORMED,
                        {
                            "status": CostEvidenceStatus.MALFORMED.value,
                            "reason": REASON_INVALID_POINT_X,
                        },
                        False,
                    )
                num_x = int(raw_x)
            elif isinstance(raw_x, str):
                s_x = raw_x.strip()
                if not (s_x.isdigit() or (s_x.startswith("-") and s_x[1:].isdigit())):
                    return (
                        CostEvidenceStatus.MALFORMED,
                        {
                            "status": CostEvidenceStatus.MALFORMED.value,
                            "reason": REASON_INVALID_POINT_X,
                        },
                        False,
                    )
                num_x = int(s_x)
            else:
                return (
                    CostEvidenceStatus.MALFORMED,
                    {
                        "status": CostEvidenceStatus.MALFORMED.value,
                        "reason": REASON_INVALID_POINT_X,
                    },
                    False,
                )

            if num_x in seen_x or (meter_id, num_x) in seen_keys:
                return (
                    CostEvidenceStatus.MALFORMED,
                    {
                        "status": CostEvidenceStatus.MALFORMED.value,
                        "reason": REASON_DUPLICATE_POINT,
                    },
                    False,
                )
            seen_x.add(num_x)
            seen_keys.add((meter_id, num_x))

            # Strict numeric parser for y: Decimal preservation
            raw_y = pt.get("y")
            if isinstance(raw_y, bool):
                return (
                    CostEvidenceStatus.MALFORMED,
                    {
                        "status": CostEvidenceStatus.MALFORMED.value,
                        "reason": REASON_QUARANTINE_NON_NUMERIC,
                    },
                    False,
                )
            if not isinstance(raw_y, (int, float, str, Decimal)):
                return (
                    CostEvidenceStatus.MALFORMED,
                    {
                        "status": CostEvidenceStatus.MALFORMED.value,
                        "reason": REASON_QUARANTINE_NON_NUMERIC,
                    },
                    False,
                )
            try:
                d_y = Decimal(str(raw_y))
            except Exception:
                return (
                    CostEvidenceStatus.MALFORMED,
                    {
                        "status": CostEvidenceStatus.MALFORMED.value,
                        "reason": REASON_QUARANTINE_NON_NUMERIC,
                    },
                    False,
                )

            if not d_y.is_finite():
                return (
                    CostEvidenceStatus.MALFORMED,
                    {
                        "status": CostEvidenceStatus.MALFORMED.value,
                        "reason": REASON_QUARANTINE_NON_FINITE,
                    },
                    False,
                )
            if d_y < 0:
                return (
                    CostEvidenceStatus.MALFORMED,
                    {
                        "status": CostEvidenceStatus.MALFORMED.value,
                        "reason": REASON_QUARANTINE_NEGATIVE,
                    },
                    False,
                )

            canonical_x = str(num_x)
            canonical_y = f"{d_y:f}"
            point_obj: dict[str, Any] = {"x": canonical_x, "y": canonical_y}

            # Dates only as parsed and re-formatted canonical dates
            raw_hs = pt.get("hs")
            if isinstance(raw_hs, dict):
                sanitized_hs: dict[str, str] = {}
                for fld in ("start", "end"):
                    val = raw_hs.get(fld)
                    if isinstance(val, str):
                        c_date = _parse_and_format_date(val)
                        if c_date is not None:
                            sanitized_hs[fld] = c_date
                        else:
                            dropped_count += 1
                    elif val is not None:
                        dropped_count += 1
                if sanitized_hs:
                    point_obj["hs"] = sanitized_hs
                extra_hs = set(raw_hs.keys()) - {"start", "end"}
                dropped_count += len(extra_hs)
            elif raw_hs is not None:
                dropped_count += 1

            extra_pt = set(pt.keys()) - {"x", "y", "hs"}
            dropped_count += len(extra_pt)

            sanitized_points.append(point_obj)

        matched_series.append(
            {
                "name": f"Meter #{placeholder}",
                "data": sanitized_points,
            }
        )

    if not matched_series:
        return (
            CostEvidenceStatus.WRONG_METER,
            {
                "status": CostEvidenceStatus.WRONG_METER.value,
                "reason": REASON_NO_AUTHORITATIVE_METER_SERIES,
            },
            False,
        )

    # Bound checks: enforce <=4 series and <=1,500 total points retained
    truncated = False
    truncation_reason: str | None = None
    if len(matched_series) > MAX_COST_SERIES:
        truncated = True
        truncation_reason = REASON_SERIES_COUNT_EXCEEDED
    if total_points > MAX_COST_POINTS:
        truncated = True
        truncation_reason = REASON_POINT_COUNT_EXCEEDED

    retained_series: list[dict[str, Any]] = []
    points_budget = MAX_COST_POINTS
    for s in matched_series[:MAX_COST_SERIES]:
        data = s["data"]
        if len(data) > points_budget:
            truncated = True
            retained_series.append({"name": s["name"], "data": data[:points_budget]})
            points_budget = 0
            break
        else:
            retained_series.append({"name": s["name"], "data": data})
            points_budget -= len(data)

    status = CostEvidenceStatus.TRUNCATED if truncated else CostEvidenceStatus.OK
    promotable = not truncated

    sample: dict[str, Any] = {
        "sample_version": 1,
        "captured_at": datetime.now(UTC).isoformat(),
        "request": {
            "start": permit.start_str,
            "end": permit.end_str,
            "usage_interval": permit.usage_interval,
            "usage_type": USAGE_TYPE_COST,
        },
        "unit": "USD",
        "status": status.value,
        "promotable": promotable,
        "series": retained_series,
        "total_points": sum(len(s["data"]) for s in retained_series),
        "dropped_count": dropped_count,
        "paired_anchors": paired_kwh_anchors or {},
    }
    if truncation_reason:
        sample["truncation_reason"] = truncation_reason

    # Enforce serialized output bound of 256 KiB
    try:
        serialized = json.dumps(sample)
        if len(serialized.encode("utf-8")) > MAX_SERIALIZED_SAMPLE_BYTES:
            sample["status"] = CostEvidenceStatus.TRUNCATED.value
            sample["promotable"] = False
            sample["series"] = []
            sample["truncation_reason"] = REASON_TOTAL_SIZE_EXCEEDED
            status = CostEvidenceStatus.TRUNCATED
            promotable = False
    except Exception:
        return (
            CostEvidenceStatus.MALFORMED,
            {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_SERIALIZATION_ERROR},
            False,
        )

    return status, sample, promotable


def bound_cost_contract_sample(
    samples: dict[str, Any] | None,
    max_bytes: int = MAX_SERIALIZED_SAMPLE_BYTES,
    max_slots: int = MAX_SAMPLE_SLOTS,
) -> dict[str, Any] | None:
    """Bound the overall cost contract sample to <= 2 slots and <= 256 KiB serialized JSON."""
    if not samples:
        return None
    res = copy.deepcopy(samples)
    if len(res) > max_slots:
        keys = list(res.keys())[:max_slots]
        res = {k: res[k] for k in keys}

    raw = json.dumps(res).encode("utf-8")
    if len(raw) <= max_bytes:
        return res

    # Mark non-promotable and truncated
    for slot in res.values():
        if isinstance(slot, dict):
            slot["status"] = CostEvidenceStatus.TRUNCATED.value
            slot["promotable"] = False
            slot["truncation_reason"] = REASON_TOTAL_SIZE_EXCEEDED

    while len(json.dumps(res).encode("utf-8")) > max_bytes:
        trimmed_any = False
        for slot in res.values():
            if isinstance(slot, dict) and "series" in slot and isinstance(slot["series"], list):
                for s in slot["series"]:
                    if isinstance(s, dict) and s.get("data"):
                        trim_cnt = max(10, len(s["data"]) // 10)
                        s["data"] = s["data"][:-trim_cnt]
                        trimmed_any = True
        if not trimmed_any:
            for slot in res.values():
                if isinstance(slot, dict):
                    slot.pop("paired_anchors", None)
            break
    return res


def execute_cost_sampler(
    seed_cookies: requests.cookies.RequestsCookieJar,
    token: str,
    permit: CostPermit,
    owner_check: Callable[[], None],
    authoritative_meters: set[str] | list[str],
    meter_placeholders: dict[str, str],
    paired_kwh_anchors: dict[str, Any] | None = None,
) -> tuple[CostEvidenceStatus, dict[str, Any], bool]:
    """Execute bounded, isolated cost sampling inside the caller thread.

    Zero detached workers. Two-dispatch sequence: POST /Dashboard/Chart then
    GET /Dashboard/ChartData. Rejects response cookies and redirects.
    """
    deadline = time.monotonic() + COST_PAIR_DEADLINE_SECONDS

    cost_session = AllowlistedSession(owner_check=owner_check)
    cost_session.allowed_hosts = frozenset({PORTAL_HOST})

    # Seed in memory and lock jar against response cookies
    rejecting_jar = RejectingCookieJar()
    for cookie in seed_cookies:
        rejecting_jar.set_cookie(cookie)
    rejecting_jar.lock()
    cost_session.cookies = rejecting_jar

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": PORTAL_BASE_URL,
        "Referer": f"{PORTAL_BASE_URL}/Dashboard",
    }

    try:
        owner_check()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return (
                CostEvidenceStatus.MALFORMED,
                {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_TIMEOUT},
                False,
            )

        post_data = {
            "__RequestVerificationToken": token,
            "UsageInterval": permit.usage_interval,
            "UsageType": USAGE_TYPE_COST,
            "jsTargetName": "StorageType",
            "EnableHoverChart": "true",
            "Start": permit.start_str,
            "End": permit.end_str,
            "IsRangeOpen": "False",
            "MaintainMaxDate": "true",
            "SelectedViaDateRange": "False",
            "ChartComparison": "1",
            "ChartComparison2": "0",
            "ChartComparison3": "0",
            "ChartComparison4": "0",
        }

        # 1. POST /Dashboard/Chart
        resp_post = cost_session.post(
            f"{PORTAL_BASE_URL}/Dashboard/Chart",
            data=post_data,
            headers=headers,
            allow_redirects=False,
            stream=True,
            timeout=min(remaining, 5.0),
        )

        body_post, err_post = _stream_response_body(resp_post, deadline, MAX_COST_BYTES)
        if err_post == "timeout":
            return (
                CostEvidenceStatus.MALFORMED,
                {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_TIMEOUT},
                False,
            )
        if err_post == "byte_cap_exceeded":
            return (
                CostEvidenceStatus.TRUNCATED,
                {
                    "status": CostEvidenceStatus.TRUNCATED.value,
                    "reason": REASON_STREAM_BYTE_CAP_EXCEEDED,
                },
                False,
            )
        if err_post is not None:
            return (
                CostEvidenceStatus.MALFORMED,
                {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_STREAM_READ_ERROR},
                False,
            )

        if resp_post.is_redirect or (300 <= resp_post.status_code < 400):
            return (
                CostEvidenceStatus.UNSUPPORTED,
                {
                    "status": CostEvidenceStatus.UNSUPPORTED.value,
                    "reason": REASON_REDIRECT,
                },
                False,
            )

        if body_post is not None and _is_login_response(resp_post, body_post):
            return (
                CostEvidenceStatus.AUTH_REJECTED,
                {"status": CostEvidenceStatus.AUTH_REJECTED.value, "reason": REASON_LOGIN_PAGE},
                False,
            )

        if resp_post.status_code != 200:
            return (
                CostEvidenceStatus.MALFORMED,
                {
                    "status": CostEvidenceStatus.MALFORMED.value,
                    "reason": REASON_HTTP_ERROR,
                },
                False,
            )

        # 2. GET /Dashboard/ChartData
        owner_check()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return (
                CostEvidenceStatus.MALFORMED,
                {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_TIMEOUT},
                False,
            )

        ts = int(time.time() * 1000)
        resp_get = cost_session.get(
            f"{PORTAL_BASE_URL}/Dashboard/ChartData",
            params={"_": ts},
            headers=headers,
            allow_redirects=False,
            stream=True,
            timeout=min(remaining, 5.0),
        )

        body_get, err_get = _stream_response_body(resp_get, deadline, MAX_COST_BYTES)
        if err_get == "timeout":
            return (
                CostEvidenceStatus.MALFORMED,
                {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_TIMEOUT},
                False,
            )
        if err_get == "byte_cap_exceeded":
            return (
                CostEvidenceStatus.TRUNCATED,
                {
                    "status": CostEvidenceStatus.TRUNCATED.value,
                    "reason": REASON_STREAM_BYTE_CAP_EXCEEDED,
                },
                False,
            )
        if err_get is not None:
            return (
                CostEvidenceStatus.MALFORMED,
                {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_STREAM_READ_ERROR},
                False,
            )

        if resp_get.is_redirect or (300 <= resp_get.status_code < 400):
            return (
                CostEvidenceStatus.UNSUPPORTED,
                {
                    "status": CostEvidenceStatus.UNSUPPORTED.value,
                    "reason": REASON_REDIRECT,
                },
                False,
            )

        if body_get is not None and _is_login_response(resp_get, body_get):
            return (
                CostEvidenceStatus.AUTH_REJECTED,
                {"status": CostEvidenceStatus.AUTH_REJECTED.value, "reason": REASON_LOGIN_PAGE},
                False,
            )

        if resp_get.status_code != 200:
            return (
                CostEvidenceStatus.MALFORMED,
                {
                    "status": CostEvidenceStatus.MALFORMED.value,
                    "reason": REASON_HTTP_ERROR,
                },
                False,
            )

        if not body_get:
            return (
                CostEvidenceStatus.MISSING,
                {"status": CostEvidenceStatus.MISSING.value, "reason": REASON_EMPTY_BODY},
                False,
            )

        try:
            payload = json.loads(body_get.decode("utf-8"))
        except Exception:
            return (
                CostEvidenceStatus.MALFORMED,
                {
                    "status": CostEvidenceStatus.MALFORMED.value,
                    "reason": REASON_JSON_DECODE_ERROR,
                },
                False,
            )

        return validate_and_sanitize_cost_payload(
            payload=payload,
            authoritative_meters=authoritative_meters,
            meter_placeholders=meter_placeholders,
            permit=permit,
            paired_kwh_anchors=paired_kwh_anchors,
        )

    except PsegTransientError:
        # Lifecycle exit (e.g. entry owner retired) must NOT be suppressed
        raise
    except PsegSecurityError:
        return (
            CostEvidenceStatus.UNSUPPORTED,
            {"status": CostEvidenceStatus.UNSUPPORTED.value, "reason": REASON_SECURITY_GUARD},
            False,
        )
    except requests.Timeout, TimeoutError:
        return (
            CostEvidenceStatus.MALFORMED,
            {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_TIMEOUT},
            False,
        )
    except requests.RequestException:
        return (
            CostEvidenceStatus.MALFORMED,
            {"status": CostEvidenceStatus.MALFORMED.value, "reason": REASON_NETWORK_ERROR},
            False,
        )
    except Exception:
        return (
            CostEvidenceStatus.MALFORMED,
            {
                "status": CostEvidenceStatus.MALFORMED.value,
                "reason": REASON_UNEXPECTED_ERROR,
            },
            False,
        )
    finally:
        cost_session.close()
