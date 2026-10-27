#!/usr/bin/env python3
"""Compare HVAC electricity estimates with hourly grid meter data (read-only)."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import json
import math
import os
import socket
import ssl
import struct
import sys
import urllib.parse
import urllib.request

MODES = ("cool", "heat_pump", "heat", "fan")
UTC = dt.UTC


def parse_time(value):
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return (result if result.tzinfo else result.astimezone()).astimezone(UTC)


def prefs_stats(prefs, grid_override=None, hvac_stat=None, no_devices=False):
    grids = []
    for source in prefs.get("energy_sources", []):
        if source.get("type") == "grid":
            flows = source.get("flow_from") or [source]
            grids.extend(f.get("stat_energy_from") for f in flows if f.get("stat_energy_from"))
    devices = [] if no_devices else [d["stat_consumption"] for d in prefs.get("device_consumption", [])
                                    if d.get("stat_consumption") and not d.get("included_in_stat")
                                    and d["stat_consumption"] != hvac_stat]
    return list(dict.fromkeys(grid_override or grids)), list(dict.fromkeys(devices))


def mode_of(attrs, state):
    if state in (None, "", "unknown", "unavailable"):
        return "unknown"
    equip = attrs.get("equipment_running")
    tokens = [s.strip().lower() for s in equip.split(",")] if isinstance(equip, str) else []
    for prefix, mode in (("compcool", "cool"), ("heatpump", "heat_pump"), ("auxheat", "heat")):
        if any(t.startswith(prefix) for t in tokens):
            return mode
    if "fan" in tokens:
        return "fan"
    return {"cooling": "cool", "drying": "cool", "heating": "heat", "preheating": "heat",
            "defrosting": "heat", "fan": "fan", "idle": "idle", "off": "idle"}.get(
                str(attrs.get("hvac_action", "")).lower(), "unknown")


def bucket_history(history, start, end):
    events = sorted(history, key=lambda e: parse_time(e.get("last_updated") or e["last_changed"]))
    buckets = {}
    # Missing initial history is unknown, rather than silently treating it as idle.
    spans = [(start, min(end, parse_time(events[0].get("last_updated") or events[0]["last_changed"])), "unknown")] if events else [(start, end, "unknown")]
    for index, event in enumerate(events):
        begin = max(start, parse_time(event.get("last_updated") or event["last_changed"]))
        finish = min(end, parse_time(events[index + 1].get("last_updated") or events[index + 1]["last_changed"]) if index + 1 < len(events) else end)
        spans.append((begin, finish, mode_of(event.get("attributes") or {}, event.get("state"))))
    for begin, finish, mode in spans:
        while begin < finish:
            hour = begin.replace(minute=0, second=0, microsecond=0)
            cut = min(finish, hour + dt.timedelta(hours=1))
            bucket = buckets.setdefault(int(hour.timestamp()), {})
            bucket[mode] = bucket.get(mode, 0) + (cut - begin).total_seconds()
            begin = cut
    return buckets


def build_rows(stats, grids, devices, runtime, start, end, hvac_stat=None):
    rows, skips = [], {"missing_stat": 0, "unknown_climate": 0, "partial_hour": 0}
    cursor = start.replace(minute=0, second=0, microsecond=0)
    needed = list(dict.fromkeys(grids + devices + ([hvac_stat] if hvac_stat else [])))
    while cursor < end:
        ts = int(cursor.timestamp())
        if cursor < start or cursor + dt.timedelta(hours=1) > end:
            skips["partial_hour"] += 1
        elif any(ts not in stats.get(s, {}) for s in needed):
            skips["missing_stat"] += 1
        elif runtime.get(ts, {}).get("unknown", 3600 if ts not in runtime else 0) > 300:
            skips["unknown_climate"] += 1
        else:
            grid = sum(stats[s][ts] for s in grids)
            other = sum(stats[s][ts] for s in devices)
            rows.append({"time": ts, "grid": grid, "other": other, "residual": grid - other,
                         "hours": {m: runtime.get(ts, {}).get(m, 0) / 3600 for m in MODES},
                         "estimate": stats[hvac_stat][ts] if hvac_stat else None})
        cursor += dt.timedelta(hours=1)
    return rows, skips


def least_squares(x, y):
    if not x or not x[0]:
        return None
    n, p = len(x), len(x[0])
    matrix = [[sum(row[i] * row[j] for row in x) for j in range(p)] +
              [float(i == j) for j in range(p)] for i in range(p)]
    for col in range(p):
        pivot = max(range(col, p), key=lambda i: abs(matrix[i][col]))
        if abs(matrix[pivot][col]) < 1e-10:
            return None
        matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
        scale = matrix[col][col]
        matrix[col] = [v / scale for v in matrix[col]]
        for i in range(p):
            if i != col:
                scale = matrix[i][col]
                matrix[i] = [a - scale * b for a, b in zip(matrix[i], matrix[col])]
    inv = [row[p:] for row in matrix]
    xy = [sum(row[i] * v for row, v in zip(x, y)) for i in range(p)]
    coef = [sum(inv[i][j] * xy[j] for j in range(p)) for i in range(p)]
    sse = sum((v - sum(a * b for a, b in zip(row, coef))) ** 2 for row, v in zip(x, y))
    variance = sse / (n - p) if n > p else None
    se = [math.sqrt(max(0, variance * inv[i][i])) if variance is not None else None for i in range(p)]
    total = sum((v - sum(y) / n) ** 2 for v in y)
    return coef, se, (1 - sse / total if total else None)


def fit_rows(rows, min_hours, with_estimate=False):
    totals = {m: sum(r["hours"][m] for r in rows) for m in MODES}
    modes = [m for m in MODES if totals[m] >= min_hours and totals[m] > 0]
    kept = [r for r in rows if not any(r["hours"][m] > 1 / 60 for m in MODES if m not in modes)]
    result = {"totals": totals, "modes": modes, "dropped": len(rows) - len(kept), "n": len(kept)}
    if not kept:
        result["fit"] = None
        return result
    result["fit"] = least_squares([[1] + [r["hours"][m] for m in modes] for r in kept], [r["residual"] for r in kept])
    result["estimate_fit"] = least_squares([[r["hours"][m] for m in modes] for r in kept], [r["estimate"] for r in kept]) if with_estimate and modes else None
    result["totals"] = {m: sum(r["hours"][m] for r in kept) for m in MODES}
    return result


def format_result(rows, skips, fit, show_hours=False):
    lines = [f"{fit['n']} usable hours; skipped: " + ", ".join(f"{k} {v}" for k, v in skips.items()) + f"; under-threshold mode hours dropped: {fit['dropped']}"]
    if show_hours:
        lines.append("UTC hour                  grid   other residual  " + " ".join(MODES))
        for r in rows:
            lines.append(f"{dt.datetime.fromtimestamp(r['time'], UTC).isoformat()} {r['grid']:.3f} {r['other']:.3f} {r['residual']:.3f} " + " ".join(f"{r['hours'][m]:.2f}" for m in MODES))
    if fit["fit"] is None:
        lines.append("Fit is singular or there are no hours left after dropping under-threshold modes; collect more varied history.")
    else:
        coef, se, r2 = fit["fit"]
        lines.append(f"Idle house load: {coef[0] * 1000:.0f} W; R²: {r2:.3f}" if r2 is not None else f"Idle house load: {coef[0] * 1000:.0f} W; R² unavailable")
        for i, mode in enumerate(fit["modes"], 1):
            watts = coef[i] * 1000
            error = se[i] * 1000 if se[i] is not None else None
            msg = f"{mode}: {watts:.0f} W ± {error:.0f} W" if error is not None else f"{mode}: {watts:.0f} W (standard error unavailable)"
            msg += f" ({fit['totals'][mode]:.2f} hours)"
            if fit.get("estimate_fit") is not None:
                msg += f"; your estimate implies {fit['estimate_fit'][0][i - 1] * 1000:.0f} W"
            if watts < 0 or (error is not None and error > abs(watts) * 0.5):
                msg += " — warning: negative or uncertain result"
            lines.append(msg)
        for i, mode in enumerate(fit["modes"], 1):
            lines.append(f"Suggested values: {mode} {coef[i] * 1000:.0f} W")
    lines.append("History recorded before a change keeps its old values.")
    return "\n".join(lines)


class Client:
    """Small read-only HA client; methods reject every other operation."""
    def __init__(self, url, token):
        self.url, self.token = url.rstrip("/"), token

    def get(self, path):
        if not (path == "/api/states" or path.startswith("/api/history/period/")):
            raise ValueError("Unsupported endpoint")
        req = urllib.request.Request(self.url + path, headers={"Authorization": "Bearer " + self.token}, method="GET")
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)

    @staticmethod
    def _exact(sock, length):
        data = bytearray()
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("WebSocket closed")
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def _send(sock, payload, opcode=1):
        mask = os.urandom(4)
        size = len(payload)
        header = bytes([0x80 | opcode, 0x80 | (size if size < 126 else 126 if size < 65536 else 127)])
        if size >= 126:
            header += struct.pack(">H" if size < 65536 else ">Q", size)
        sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    @classmethod
    def _receive(cls, sock):
        parts = []
        while True:
            a, b = cls._exact(sock, 2)
            length = b & 127
            if length >= 126:
                length = struct.unpack(">H" if length == 126 else ">Q", cls._exact(sock, 2 if length == 126 else 8))[0]
            mask = cls._exact(sock, 4) if b & 128 else None
            data = cls._exact(sock, length)
            if mask:
                data = bytes(v ^ mask[i % 4] for i, v in enumerate(data))
            opcode = a & 15
            if opcode == 8:
                raise ConnectionError("WebSocket closed")
            if opcode == 9:
                cls._send(sock, data, 10)
            elif opcode in (0, 1):
                parts.append(data)
                if a & 128:
                    return json.loads(b"".join(parts))

    def ws(self, command):
        if command.get("type") not in ("energy/get_prefs", "recorder/statistics_during_period"):
            raise ValueError("Unsupported command")
        url = urllib.parse.urlsplit(self.url)
        if url.scheme not in ("http", "https") or not url.hostname:
            raise ValueError("HA_URL must be an http or https URL")
        port = url.port or (443 if url.scheme == "https" else 80)
        sock = socket.create_connection((url.hostname, port), timeout=60)
        if url.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=url.hostname)
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            path = url.path.rstrip("/") + "/api/websocket"
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {url.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
            # Read one byte at a time to avoid consuming the first frame.
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                headers.extend(self._exact(sock, 1))
                if len(headers) > 65536:
                    raise ConnectionError("WebSocket handshake too large")
            expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).lower()
            if not headers.startswith(b"HTTP/1.1 101 ") or expected not in bytes(headers).lower():
                raise ConnectionError("WebSocket handshake failed")
            if self._receive(sock).get("type") != "auth_required":
                raise ConnectionError("Unexpected authentication response")
            self._send(sock, json.dumps({"type": "auth", "access_token": self.token}).encode())
            if self._receive(sock).get("type") != "auth_ok":
                raise ConnectionError("Home Assistant authentication failed")
            self._send(sock, json.dumps({**command, "id": 1}).encode())
            while True:
                response = self._receive(sock)
                if response.get("id") == 1:
                    if not response.get("success"):
                        raise ConnectionError("Home Assistant request failed")
                    return response["result"]
        finally:
            sock.close()


def main(argv=None, client_factory=Client):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--climate")
    parser.add_argument("--grid-stat", action="append")
    parser.add_argument("--hvac-stat")
    parser.add_argument("--no-devices", action="store_true")
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--min-hours", type=float, default=2.0)
    parser.add_argument("--hours", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        end = parse_time(args.end) if args.end else dt.datetime.now(UTC)
        start = parse_time(args.start) if args.start else end - dt.timedelta(days=14)
        if start >= end or not math.isfinite(args.min_hours) or args.min_hours < 0:
            raise ValueError("Invalid time range or minimum hours")
        token = os.environ.get("HA_TOKEN") or os.environ.get("HOMEASSISTANT_TOKEN")
        if not token and sys.stdin.isatty():
            token = getpass.getpass("Home Assistant long-lived token: ")
        if not token:
            raise ValueError("Set HA_TOKEN or HOMEASSISTANT_TOKEN to a long-lived token")
        client = client_factory(os.environ.get("HA_URL", "http://homeassistant.local:8123"), token)
        climates = sorted(s["entity_id"] for s in client.get("/api/states") if s.get("entity_id", "").startswith("climate."))
        if not args.climate and len(climates) != 1:
            raise ValueError("Specify --climate; available climate entities: " + (", ".join(climates) or "none"))
        climate = args.climate or climates[0]
        grids, devices = prefs_stats(client.ws({"type": "energy/get_prefs"}), args.grid_stat, args.hvac_stat, args.no_devices)
        if not grids:
            raise ValueError("No grid import statistic found; specify --grid-stat")
        ids = list(dict.fromkeys(grids + devices + ([args.hvac_stat] if args.hvac_stat else [])))
        raw = client.ws({"type": "recorder/statistics_during_period", "start_time": start.isoformat(), "end_time": end.isoformat(), "statistic_ids": ids, "period": "hour", "types": ["change"]})
        stats = {sid: {int(p["start"] / 1000): p["change"] for p in points if p.get("change") is not None} for sid, points in raw.items()}
        path = "/api/history/period/" + urllib.parse.quote(start.isoformat(), safe="") + "?" + urllib.parse.urlencode({"filter_entity_id": climate, "end_time": end.isoformat()})
        history = client.get(path)
        runtime = bucket_history(history[0] if history else [], start, end)
        rows, skips = build_rows(stats, grids, devices, runtime, start, end, args.hvac_stat)
        if not rows:
            print(json.dumps({"error": "No usable hours", "skips": skips}) if args.json else "No usable hours; skipped: " + ", ".join(f"{k} {v}" for k, v in skips.items()))
            return 1
        fit = fit_rows(rows, args.min_hours, bool(args.hvac_stat))
        if not fit["n"]:
            print(json.dumps({"error": "No usable hours after filtering", "skips": skips, "result": fit}) if args.json else "No usable hours after filtering under-threshold modes.")
            return 1
        print(json.dumps({"rows": rows if args.hours else [], "skips": skips, "result": fit}) if args.json else format_result(rows, skips, fit, args.hours))
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        # Never show server responses, URLs with credentials, or the token in exceptions.
        message = str(exc) if isinstance(exc, ValueError) and str(exc) in ("Invalid time range or minimum hours", "Set HA_TOKEN or HOMEASSISTANT_TOKEN to a long-lived token", "No grid import statistic found; specify --grid-stat") or isinstance(exc, ValueError) and str(exc).startswith("Specify --climate;") else "Connection, authentication, or data error; check HA_URL and token."
        print(message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
