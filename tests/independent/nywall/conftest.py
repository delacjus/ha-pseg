"""Pytest fixtures and configuration for independent NY-wall contract tests.

Preserves the uninitialized client harness and synthetic point generation from
the archived R1/R2 review probes without requiring network, portal credentials,
or active Home Assistant runtime services.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime
from typing import Any

import pytest

from custom_components.pseg.pseg_client import PsegClient


@pytest.fixture
def uninitialized_client() -> PsegClient:
    """Provide an uninitialized PsegClient instance bypassing network init."""
    return object.__new__(PsegClient)


@pytest.fixture
def base_day() -> date:
    """Return the primary EDT reference day (2026-10-15) used across review probes."""
    return date(2026, 10, 15)


@pytest.fixture
def point_factory() -> Callable[..., dict[str, Any]]:
    """Factory creating synthetic chart points with America/New_York wall timestamps."""

    def _make_point(
        day: date,
        hour: int,
        value: float,
        start_label: str | None = None,
        end_label: str | None = None,
    ) -> dict[str, Any]:
        wall = datetime(day.year, day.month, day.day, hour, tzinfo=UTC)
        default_label = day.strftime("%m/%d/%Y")
        sl = default_label if start_label is None else start_label
        el = default_label if end_label is None else end_label
        return {
            "x": int(wall.timestamp() * 1000),
            "y": value,
            "hs": {"start": sl, "end": el},
        }

    return _make_point


@pytest.fixture
def base_varying_points(
    base_day: date, point_factory: Callable[..., dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return 24-hour finite varying-load points matching the R1/R2 baseline."""
    return [
        point_factory(base_day, h, round(0.4 + (h % 7) * 0.13, 4))
        for h in range(24)
    ]


@pytest.fixture
def base_varying_total(base_varying_points: list[dict[str, Any]]) -> float:
    """Return the authoritative daily total for the base varying-load points."""
    return round(sum(p["y"] for p in base_varying_points), 4)
