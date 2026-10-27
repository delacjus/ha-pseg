"""Offline checks for the standalone calibration tool."""
import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("hvac_calibration_check", Path(__file__).parents[1] / "tools/hvac_calibration_check.py")
hvac = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hvac)


def test_modes():
    assert hvac.mode_of({"equipment_running": "fan, AuxHeat1, HeatPump2, CompCool1"}, "heat") == "cool"
    assert hvac.mode_of({"equipment_running": "fan, HeatPump1"}, "heat") == "heat_pump"
    assert hvac.mode_of({"equipment_running": "AUXHEAT2"}, "heat") == "heat"
    assert hvac.mode_of({"hvac_action": "drying"}, "cool") == "cool"
    assert hvac.mode_of({"hvac_action": "preheating"}, "heat") == "heat"
    assert hvac.mode_of({"hvac_action": "defrosting"}, "heat") == "heat"
    assert hvac.mode_of({"hvac_action": "fan"}, "fan") == "fan"
    assert hvac.mode_of({"hvac_action": "off"}, "off") == "idle"
    assert hvac.mode_of({}, "unavailable") == "unknown"


def test_buckets_clip_and_split():
    start = hvac.parse_time("2026-01-01T00:30:00Z")
    end = hvac.parse_time("2026-01-01T02:00:00Z")
    history = [{"last_changed": "2026-01-01T00:00:00Z", "state": "heat", "attributes": {"hvac_action": "heating"}},
               {"last_changed": "2026-01-01T01:15:00Z", "state": "off", "attributes": {"hvac_action": "idle"}}]
    buckets = hvac.bucket_history(history, start, end)
    assert buckets[int(start.timestamp()) - 1800] == {"heat": 1800}
    assert buckets[int(start.timestamp()) + 1800] == {"heat": 900, "idle": 2700}


def test_prefs():
    prefs = {"energy_sources": [{"type": "grid", "flow_from": [{"stat_energy_from": "g1"}, {"stat_energy_from": "g2"}]}, {"type": "grid", "stat_energy_from": "g3"}], "device_consumption": [{"stat_consumption": "d"}, {"stat_consumption": "child", "included_in_stat": "d"}, {"stat_consumption": "hvac"}]}
    assert hvac.prefs_stats(prefs, hvac_stat="hvac") == (["g1", "g2", "g3"], ["d"])
    assert hvac.prefs_stats(prefs, ["override"], no_devices=True) == (["override"], [])


def test_skips():
    start = hvac.parse_time("2026-01-01T00:00:00Z")
    t = int(start.timestamp())
    stats = {"g": {t: 1, t + 3600: 2, t + 7200: 3}, "d": {t: 0.2, t + 7200: 0.3}}
    runtime = {t: {"idle": 3600}, t + 3600: {"idle": 3600}, t + 7200: {"unknown": 301}}
    rows, skips = hvac.build_rows(stats, ["g"], ["d"], runtime, start, start + dt.timedelta(hours=3))
    assert rows[0]["residual"] == pytest.approx(0.8)
    assert skips == {"missing_stat": 1, "unknown_climate": 1, "partial_hour": 0}


def synthetic_rows():
    rows = []
    for i, (heat, cool) in enumerate([(0, 0), (1, 0), (0, 1), (.5, 0), (0, .5), (.5, .5), (1, 0), (0, 1), (0, 0)]):
        rows.append({"hours": {"heat": heat, "cool": cool, "fan": 0, "heat_pump": 0}, "residual": .180 + .090 * heat + 2.6 * cool + (0.001 if i % 2 else -0.001), "estimate": .1 * heat + 2.8 * cool})
    return rows


def test_fit_declared_watts_and_estimate():
    fit = hvac.fit_rows(synthetic_rows(), 2, True)
    coef, se, r2 = fit["fit"]
    assert fit["modes"] == ["cool", "heat"]
    assert coef[0] * 1000 == pytest.approx(180, abs=2)
    assert coef[1] * 1000 == pytest.approx(2600, abs=2)
    assert coef[2] * 1000 == pytest.approx(90, abs=2)
    assert se[1] > 0 and r2 > .99
    assert fit["estimate_fit"][0] == pytest.approx([2.8, .1])


def test_singular_and_threshold():
    rows = synthetic_rows()
    rows[0]["hours"]["fan"] = .5
    fit = hvac.fit_rows(rows, 2)
    assert fit["dropped"] == 1
    assert hvac.least_squares([[1, 1], [1, 1], [1, 1]], [1, 2, 3]) is None


def test_cli_fake_and_read_only(monkeypatch, capsys):
    calls = []
    start = hvac.parse_time("2026-01-01T00:00:00Z")
    class Fake:
        def __init__(self, url, token):
            assert token == "secret-token"
        def get(self, path):
            calls.append(("GET", path))
            if path == "/api/states":
                return [{"entity_id": "climate.home"}]
            return [[{"last_changed": start.isoformat(), "state": "off", "attributes": {"hvac_action": "idle"}}]]
        def ws(self, command):
            calls.append(("WS", command["type"]))
            if command["type"] == "energy/get_prefs":
                return {"energy_sources": [{"type": "grid", "stat_energy_from": "grid"}]}
            assert command["units"] == {"energy": "kWh"}
            return {"grid": [{"start": int((start + dt.timedelta(hours=i)).timestamp() * 1000), "change": .18} for i in range(3)]}
    monkeypatch.setenv("HA_TOKEN", "secret-token")
    assert hvac.main(["--start", start.isoformat(), "--end", (start + dt.timedelta(hours=3)).isoformat(), "--json"], Fake) == 0
    output = capsys.readouterr()
    assert "secret-token" not in output.out + output.err
    assert json.loads(output.out)["result"]["n"] == 3
    assert [c[1] for c in calls if c[0] == "WS"] == ["energy/get_prefs", "recorder/statistics_during_period"]
    assert all(c[0] in ("GET", "WS") for c in calls)
    assert all(c[1] == "/api/states" or c[1].startswith("/api/history/period/") for c in calls if c[0] == "GET")
    with pytest.raises(ValueError):
        hvac.Client("http://localhost", "secret-token").ws({"type": "anything_else"})
    with pytest.raises(ValueError):
        hvac.Client("http://localhost", "secret-token").get("/api/services")


def test_threshold_rechecked_after_mixed_hour_dropped():
    rows = synthetic_rows()[:5]
    for row, cool, fan in zip(rows, [1, 1, .5, 0, 0], [.001, 0, 0, 0, 0]):
        row["hours"].update(cool=cool, fan=fan, heat=0)
    fit = hvac.fit_rows(rows, 2)
    assert "cool" not in fit["modes"]
    assert fit["dropped"] == 3


def test_socket_fragment_extended_length_and_ping():
    class Socket:
        def __init__(self):
            self.data = bytearray(b'\x01\x7e\x00\x82' + b'{"value":"' + b'a' * 120 + b'\x89\x02hi\x80\x02"}')
            self.sent = b""
        def recv(self, size):
            result = self.data[:size]
            del self.data[:size]
            return bytes(result)
        def sendall(self, data):
            self.sent = data
    sock = Socket()
    assert hvac.Client._receive(sock) == {"value": "a" * 120}
    assert sock.sent[:2] == b"\x8a\x82"
    assert bytes(b ^ sock.sent[2 + i % 4] for i, b in enumerate(sock.sent[6:])) == b"hi"


def test_connection_failure_hides_token(monkeypatch, capsys):
    class Fake:
        def __init__(self, url, token):
            raise OSError("secret-token")
    monkeypatch.setenv("HA_TOKEN", "secret-token")
    assert hvac.main([], Fake) == 2
    output = capsys.readouterr()
    assert "secret-token" not in output.out + output.err
    assert "Connection, authentication, or data error" in output.err


def test_cli_hvac_stat_and_no_devices(monkeypatch, capsys):
    start = hvac.parse_time("2026-01-01T00:00:00Z")
    commands = []
    class Fake:
        def __init__(self, url, token):
            pass
        def get(self, path):
            if path == "/api/states":
                return [{"entity_id": "climate.home"}]
            return [[{"last_changed": (start + dt.timedelta(hours=i)).isoformat(), "state": "on", "attributes": {"hvac_action": action}} for i, action in enumerate(["idle", "heating", "idle", "heating", "idle"])]]
        def ws(self, command):
            if command["type"] == "energy/get_prefs":
                return {"energy_sources": [{"type": "grid", "stat_energy_from": "grid"}], "device_consumption": [{"stat_consumption": "device"}, {"stat_consumption": "hvac"}]}
            commands.append(command)
            values = {"grid": [.2, .3, .2, .3, .2], "device": [.02] * 5, "hvac": [0, .5, 0, .5, 0]}
            return {sid: [{"start": int((start + dt.timedelta(hours=i)).timestamp() * 1000), "change": v} for i, v in enumerate(values[sid])] for sid in command["statistic_ids"]}
    monkeypatch.setenv("HA_TOKEN", "secret-token")
    args = ["--start", start.isoformat(), "--end", (start + dt.timedelta(hours=5)).isoformat(), "--hvac-stat", "hvac"]
    assert hvac.main(args, Fake) == 0
    assert commands[-1]["statistic_ids"] == ["grid", "device", "hvac"]
    assert "heat: 100 W" in capsys.readouterr().out
    assert hvac.main(args + ["--no-devices"], Fake) == 0
    assert commands[-1]["statistic_ids"] == ["grid", "hvac"]
    assert "your estimate implies 500 W" in capsys.readouterr().out


def test_unreliable_suggestions():
    fit = {"n": 4, "dropped": 0, "modes": ["cool", "heat"], "totals": {"cool": 2, "heat": 2}, "fit": ([.18, -.1, .1], [.01, .01, .06], .5)}
    output = hvac.format_result([], {}, fit)
    assert "Suggested values:" not in output
    assert output.count("no reliable value yet — collect more hours") == 2


def test_cli_insufficient_fit(monkeypatch, capsys):
    start = hvac.parse_time("2026-01-01T00:00:00Z")
    class Fake:
        action = "heating"
        def __init__(self, url, token):
            pass
        def get(self, path):
            if path == "/api/states":
                return [{"entity_id": "climate.home"}]
            return [[{"last_changed": start.isoformat(), "state": "on", "attributes": {"hvac_action": self.action}}]]
        def ws(self, command):
            if command["type"] == "energy/get_prefs":
                return {"energy_sources": [{"type": "grid", "stat_energy_from": "grid"}]}
            return {"grid": [{"start": int(start.timestamp() * 1000), "change": .3}]}
    monkeypatch.setenv("HA_TOKEN", "secret-token")
    args = ["--start", start.isoformat(), "--end", (start + dt.timedelta(hours=1)).isoformat()]
    assert hvac.main(args + ["--min-hours", "1"], Fake) == 1
    assert "not enough varied data" in capsys.readouterr().out
    Fake.action = "idle"
    assert hvac.main(args + ["--json"], Fake) == 1
    assert json.loads(capsys.readouterr().out)["error"] == "not enough varied data"
