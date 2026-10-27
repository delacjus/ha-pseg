#!/usr/bin/env python3
"""Deterministic constrained pairwise generator and covering checker (P2-08).

The checked-in covering file (``tests/systemic/response_covering.json``) declares
the G3 axes, every applicability exclusion *with a reason*, and the covering rows.
This tool never imports the test suite or production code: it re-derives the valid
tuples and every required pair from the declared domains and exclusions alone.

Usage::

    python tools/pairwise.py --check tests/systemic/response_covering.json
    python tools/pairwise.py --generate tests/systemic/response_covering.json
    python tools/pairwise.py --write tests/systemic/response_covering.json

``--check`` exits 0 only when the file is well formed, every row is a valid tuple
and every valid pair is covered by at least one row. ``--generate`` prints the
deterministically generated rows for the declared axes/exclusions; ``--write``
rewrites the rows in place with those rows (every row keeps a stable ``tier``
assignment from :func:`assign_tiers`).

Stdlib only, stable seed and stable output order.
"""

from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
import random
import sys
from typing import Any

PAIRWISE_AXES: tuple[str, ...] = (
    "stage",
    "kind",
    "cookie",
    "position",
    "flow",
    "event",
    "family",
)
NIGHTLY_AXES: tuple[str, ...] = ("stage", "kind", "cookie", "position")

#: Axis pairs that must be covered. Declared explicitly so the checker's pair
#: arithmetic is auditable; every pairwise combination of axes is included.
AXIS_PAIRS: tuple[tuple[str, str], ...] = tuple(itertools.combinations(PAIRWISE_AXES, 2))

#: Mandatory fast representatives. Every one must exist as a row and be ``fast``.
MANDATORY_FAST: tuple[dict[str, Any], ...] = (
    {
        "id": "mandatory:307-credential-repost",
        "stage": "hourly_chart",
        "kind": "307",
        "cookie": "none",
        "position": "post_proof",
        "flow": "L",
        "event": "poll",
        "family": "client",
        "note": "307 re-POST keeps the credential body digest on the redirect hop",
    },
    {
        "id": "mandatory:308-credential-repost",
        "stage": "hourly_chart",
        "kind": "308",
        "cookie": "none",
        "position": "post_proof",
        "flow": "L",
        "event": "poll",
        "family": "client",
        "note": "308 re-POST keeps the credential body digest on the redirect hop",
    },
    {
        "id": "mandatory:healthy-hourly-rotation",
        "stage": "hourly_chart_data",
        "kind": "valid_success",
        "cookie": "sid",
        "position": "optional",
        "flow": "L",
        "event": "poll",
        "family": "ha",
        "note": "healthy hourly rotation advances the latest checkpoint",
    },
    {
        "id": "mandatory:auth-on-hourly-is-auth-loss",
        "stage": "hourly_chart_data",
        "kind": "401",
        "cookie": "none",
        "position": "optional",
        "flow": "L",
        "event": "poll",
        "family": "ha",
        "note": "hourly-leg auth failure is typed auth loss, never a daily fallback",
    },
    {
        "id": "mandatory:non-auth-hourly-daily-fallback",
        "stage": "hourly_chart_data",
        "kind": "500",
        "cookie": "none",
        "position": "optional",
        "flow": "L",
        "event": "poll",
        "family": "ha",
        "note": "non-auth hourly failure delivers the defined daily fallback",
    },
    {
        "id": "mandatory:post-proof-poison-only-follow-on",
        "stage": "hourly_chart_data",
        "kind": "503",
        "cookie": "aux",
        "position": "post_proof",
        "flow": "L",
        "event": "poll",
        "family": "ha",
        "note": "last leg of the call: only the follow-on shows a persisted poison",
    },
    {
        "id": "mandatory:login-form-get-is-the-real-get",
        "stage": "login_form_get",
        "kind": "500",
        "cookie": "none",
        "position": "pre_proof",
        "flow": "L",
        "event": "poll",
        "family": "client",
        "note": "the login form stage answers the real GET / token read, not POST /Home/Login",
    },
    {
        "id": "mandatory:sso-keepalive-acs-relay",
        "stage": "saml_acs",
        "kind": "500",
        "cookie": "none",
        "position": "pre_proof",
        "flow": "S",
        "event": "keepalive",
        "family": "client",
        "note": "SSO keepalive really posts ACS (SignIn -> ACS -> Dashboard); the failed relay reply is consumed and quarantined",
    },
)

#: Reviewed fast-tier rows the greedy reselection must never drop.
#:
#: The B3 login-stage relabel re-ran tier assignment; without these pins it dropped
#: unrelated former fast rows (F3, review-r1 2026-10-27) and demoted the reviewed fast
#: set to a fresh greedy sample. Pins are tier-only: they add no pair requirement and
#: every entry is a valid declared tuple. ``mandatory:*`` rows above stay the named
#: finding proofs; these rows are the historical/reviewed fast membership.
PRESERVED_FAST: tuple[dict[str, Any], ...] = (
    {
        "id": "daily_chart_data::maintenance::none::post_proof::S::setup::ha",
        "stage": "daily_chart_data",
        "kind": "maintenance",
        "cookie": "none",
        "position": "post_proof",
        "flow": "S",
        "event": "setup",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "daily_chart_data::missing_token::aux::post_proof::R::setup::ha",
        "stage": "daily_chart_data",
        "kind": "missing_token",
        "cookie": "aux",
        "position": "post_proof",
        "flow": "R",
        "event": "setup",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "daily_chart_data::root_number::remember_me::post_proof::H::poll::client",
        "stage": "daily_chart_data",
        "kind": "root_number",
        "cookie": "remember_me",
        "position": "post_proof",
        "flow": "H",
        "event": "poll",
        "family": "client",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "dashboard_verify_token::403::aux::post_proof::L::keepalive::ha",
        "stage": "dashboard_verify_token",
        "kind": "403",
        "cookie": "aux",
        "position": "post_proof",
        "flow": "L",
        "event": "keepalive",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "dashboard_verify_token::429::none::pre_proof::H::backfill::ha",
        "stage": "dashboard_verify_token",
        "kind": "429",
        "cookie": "none",
        "position": "pre_proof",
        "flow": "H",
        "event": "backfill",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "dashboard_verify_token::all_invalid::remember_me::pre_proof::R::setup::ha",
        "stage": "dashboard_verify_token",
        "kind": "all_invalid",
        "cookie": "remember_me",
        "position": "pre_proof",
        "flow": "R",
        "event": "setup",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "dashboard_verify_token::empty::aux::pre_proof::L::poll::client",
        "stage": "dashboard_verify_token",
        "kind": "empty",
        "cookie": "aux",
        "position": "pre_proof",
        "flow": "L",
        "event": "poll",
        "family": "client",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "history_chunk::root_null::remember_me::post_proof::L::backfill::client",
        "stage": "history_chunk",
        "kind": "root_null",
        "cookie": "remember_me",
        "position": "post_proof",
        "flow": "L",
        "event": "backfill",
        "family": "client",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "history_chunk::truncated_json::sid::post_proof::R::backfill::client",
        "stage": "history_chunk",
        "kind": "truncated_json",
        "cookie": "sid",
        "position": "post_proof",
        "flow": "R",
        "event": "backfill",
        "family": "client",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "history_chunk::unrelated::aux::post_proof::S::backfill::ha",
        "stage": "history_chunk",
        "kind": "unrelated",
        "cookie": "aux",
        "position": "post_proof",
        "flow": "S",
        "event": "backfill",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "hourly_chart::302_login::none::post_proof::R::setup::ha",
        "stage": "hourly_chart",
        "kind": "302_login",
        "cookie": "none",
        "position": "post_proof",
        "flow": "R",
        "event": "setup",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "hourly_chart::404::aux::optional::H::setup::client",
        "stage": "hourly_chart",
        "kind": "404",
        "cookie": "aux",
        "position": "optional",
        "flow": "H",
        "event": "setup",
        "family": "client",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "hourly_chart_data::root_array::remember_me::optional::R::poll::client",
        "stage": "hourly_chart_data",
        "kind": "root_array",
        "cookie": "remember_me",
        "position": "optional",
        "flow": "R",
        "event": "poll",
        "family": "client",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "hourly_chart_data::root_string::none::post_proof::S::setup::client",
        "stage": "hourly_chart_data",
        "kind": "root_string",
        "cookie": "none",
        "position": "post_proof",
        "flow": "S",
        "event": "setup",
        "family": "client",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "login_form_get::connection_error::remember_me::pre_proof::L::poll::ha",
        "stage": "login_form_get",
        "kind": "connection_error",
        "cookie": "remember_me",
        "position": "pre_proof",
        "flow": "L",
        "event": "poll",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "saml_acs::timeout::aux::pre_proof::S::poll::ha",
        "stage": "saml_acs",
        "kind": "timeout",
        "cookie": "aux",
        "position": "pre_proof",
        "flow": "S",
        "event": "poll",
        "family": "ha",
        "note": "former fast row (F3): reselection must not drop a reviewed fast case",
    },
    {
        "id": "daily_chart_data::connection_error::sid::post_proof::R::setup::client",
        "stage": "daily_chart_data",
        "kind": "connection_error",
        "cookie": "sid",
        "position": "post_proof",
        "flow": "R",
        "event": "setup",
        "family": "client",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "daily_chart_data::missing_token::none::post_proof::H::poll::ha",
        "stage": "daily_chart_data",
        "kind": "missing_token",
        "cookie": "none",
        "position": "post_proof",
        "flow": "H",
        "event": "poll",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "daily_chart_data::root_string::remember_me::post_proof::L::setup::client",
        "stage": "daily_chart_data",
        "kind": "root_string",
        "cookie": "remember_me",
        "position": "post_proof",
        "flow": "L",
        "event": "setup",
        "family": "client",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "daily_chart_data::unrelated::aux::post_proof::S::setup::ha",
        "stage": "daily_chart_data",
        "kind": "unrelated",
        "cookie": "aux",
        "position": "post_proof",
        "flow": "S",
        "event": "setup",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "dashboard_verify_token::403::sid::post_proof::S::keepalive::ha",
        "stage": "dashboard_verify_token",
        "kind": "403",
        "cookie": "sid",
        "position": "post_proof",
        "flow": "S",
        "event": "keepalive",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "dashboard_verify_token::429::remember_me::pre_proof::R::backfill::ha",
        "stage": "dashboard_verify_token",
        "kind": "429",
        "cookie": "remember_me",
        "position": "pre_proof",
        "flow": "R",
        "event": "backfill",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "dashboard_verify_token::empty::none::pre_proof::H::backfill::ha",
        "stage": "dashboard_verify_token",
        "kind": "empty",
        "cookie": "none",
        "position": "pre_proof",
        "flow": "H",
        "event": "backfill",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "dashboard_verify_token::maintenance::aux::pre_proof::L::setup::client",
        "stage": "dashboard_verify_token",
        "kind": "maintenance",
        "cookie": "aux",
        "position": "pre_proof",
        "flow": "L",
        "event": "setup",
        "family": "client",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "history_chunk::302_login::none::post_proof::R::poll::ha",
        "stage": "history_chunk",
        "kind": "302_login",
        "cookie": "none",
        "position": "post_proof",
        "flow": "R",
        "event": "poll",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "history_chunk::all_invalid::sid::post_proof::L::backfill::client",
        "stage": "history_chunk",
        "kind": "all_invalid",
        "cookie": "sid",
        "position": "post_proof",
        "flow": "L",
        "event": "backfill",
        "family": "client",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "history_chunk::root_null::aux::post_proof::S::backfill::ha",
        "stage": "history_chunk",
        "kind": "root_null",
        "cookie": "aux",
        "position": "post_proof",
        "flow": "S",
        "event": "backfill",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "history_chunk::root_number::remember_me::post_proof::H::backfill::client",
        "stage": "history_chunk",
        "kind": "root_number",
        "cookie": "remember_me",
        "position": "post_proof",
        "flow": "H",
        "event": "backfill",
        "family": "client",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "hourly_chart::timeout::aux::optional::H::setup::ha",
        "stage": "hourly_chart",
        "kind": "timeout",
        "cookie": "aux",
        "position": "optional",
        "flow": "H",
        "event": "setup",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "hourly_chart_data::404::remember_me::optional::R::poll::client",
        "stage": "hourly_chart_data",
        "kind": "404",
        "cookie": "remember_me",
        "position": "optional",
        "flow": "R",
        "event": "poll",
        "family": "client",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "hourly_chart_data::root_array::none::optional::S::setup::client",
        "stage": "hourly_chart_data",
        "kind": "root_array",
        "cookie": "none",
        "position": "optional",
        "flow": "S",
        "event": "setup",
        "family": "client",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "hourly_chart_data::truncated_json::aux::optional::L::setup::ha",
        "stage": "hourly_chart_data",
        "kind": "truncated_json",
        "cookie": "aux",
        "position": "optional",
        "flow": "L",
        "event": "setup",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "login_post::captcha::none::post_proof::L::poll::ha",
        "stage": "login_post",
        "kind": "captcha",
        "cookie": "none",
        "position": "post_proof",
        "flow": "L",
        "event": "poll",
        "family": "ha",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
    {
        "id": "login_post::timeout::sid::pre_proof::L::poll::client",
        "stage": "login_post",
        "kind": "timeout",
        "cookie": "sid",
        "position": "pre_proof",
        "flow": "L",
        "event": "poll",
        "family": "client",
        "note": "current fast row (F3): reselection must not demote a reviewed fast case",
    },
)


def pinned_rows() -> tuple[dict[str, Any], ...]:
    """Every row generation and checking must keep in the fast tier."""
    return MANDATORY_FAST + PRESERVED_FAST


class ModelError(ValueError):
    """Raised when the covering file is structurally invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ModelError(message)


def load_model(path: str | Path) -> dict[str, Any]:
    """Load and structurally validate a covering file."""
    with Path(path).open(encoding="utf-8") as handle:
        model = json.load(handle)
    validate_model(model)
    return model


def validate_model(model: dict[str, Any]) -> None:
    """Validate axis declarations, exclusions and rows (structure only)."""
    _require(isinstance(model, dict), "covering model must be a JSON object")
    axes = model.get("axes")
    _require(isinstance(axes, dict), "covering model needs an 'axes' object")
    for axis in PAIRWISE_AXES:
        values = axes.get(axis)
        _require(isinstance(values, list) and values, f"axis '{axis}' needs a non-empty list")
        _require(len(set(map(str, values))) == len(values), f"axis '{axis}' has duplicate values")
    _require(isinstance(model.get("seed"), int), "covering model needs an integer seed")
    exclusions = model.get("exclusions")
    _require(isinstance(exclusions, list), "covering model needs an 'exclusions' list")
    for index, exclusion in enumerate(exclusions):
        where = f"exclusion[{index}]"
        _require(isinstance(exclusion, dict), f"{where} must be an object")
        _require(
            exclusion.get("axis") in PAIRWISE_AXES,
            f"{where}: axis must be one of {PAIRWISE_AXES}",
        )
        values = exclusion.get("values")
        _require(
            isinstance(values, list) and values,
            f"{where}: 'values' must be a non-empty list",
        )
        declared = {str(value) for value in axes[exclusion["axis"]]}
        unknown = {str(value) for value in values} - declared
        _require(not unknown, f"{where}: unknown values {sorted(unknown)}")
        context = exclusion.get("context", {})
        _require(isinstance(context, dict), f"{where}: 'context' must be an object")
        for context_axis, context_values in context.items():
            _require(
                context_axis in PAIRWISE_AXES and context_axis != exclusion["axis"],
                f"{where}: bad context axis '{context_axis}'",
            )
            _require(
                isinstance(context_values, list) and context_values,
                f"{where}: context axis '{context_axis}' needs a list",
            )
            unknown = {str(value) for value in context_values} - {
                str(value) for value in axes[context_axis]
            }
            _require(
                not unknown,
                f"{where}: unknown context values {sorted(unknown)} for '{context_axis}'",
            )
        scope = exclusion.get("scope", ["pairwise", "nightly"])
        _require(
            isinstance(scope, list) and scope and set(scope) <= {"pairwise", "nightly"},
            f"{where}: scope must be a non-empty subset of pairwise/nightly",
        )
        reason = exclusion.get("reason")
        _require(
            isinstance(reason, str) and reason.strip(),
            f"{where}: every exclusion needs a non-empty reason",
        )
    rows = model.get("rows")
    _require(isinstance(rows, list), "covering model needs a 'rows' list")
    model_only = model.get("model_only", [])
    _require(isinstance(model_only, list), "'model_only' must be a list")
    for index, entry in enumerate(model_only):
        where = f"model_only[{index}]"
        _require(isinstance(entry, dict), f"{where} must be an object")
        _require(
            entry.get("axis") in NIGHTLY_AXES,
            f"{where}: axis must be one of the core axes {NIGHTLY_AXES}",
        )
        _require(
            str(entry.get("value")) in {str(value) for value in axes[entry["axis"]]},
            f"{where}: value outside axis '{entry.get('axis')}'",
        )
        _require(
            isinstance(entry.get("reason"), str) and entry["reason"].strip(),
            f"{where}: needs a non-empty reason",
        )
    seen: set[str] = set()
    for index, row in enumerate(rows):
        where = f"row[{index}]"
        _require(isinstance(row, dict), f"{where} must be an object")
        row_id = row.get("id")
        _require(isinstance(row_id, str) and row_id, f"{where}: needs a string id")
        _require(row_id not in seen, f"{where}: duplicate row id '{row_id}'")
        seen.add(row_id)
        for axis in PAIRWISE_AXES:
            value = row.get(axis)
            _require(value is not None, f"{where}: missing axis '{axis}'")
            _require(
                str(value) in {str(v) for v in axes[axis]},
                f"{where}: value {value!r} is outside axis '{axis}'",
            )
        _require(
            row.get("tier") in {"fast", "slow", "nightly"},
            f"{where}: tier must be fast/slow/nightly",
        )


def _matches(exclusion: dict[str, Any], values: dict[str, str]) -> bool:
    """Return True when a concrete tuple matches the declared exclusion."""
    if exclusion["axis"] not in values:
        # An exclusion about an axis this domain does not model cannot apply.
        return False
    if values[exclusion["axis"]] not in {str(v) for v in exclusion["values"]}:
        return False
    for context_axis, context_values in exclusion.get("context", {}).items():
        if context_axis not in values:
            return False
        if values[context_axis] not in {str(v) for v in context_values}:
            return False
    return True


def is_excluded(model: dict[str, Any], values: dict[str, str], scope: str) -> str | None:
    """Return the first matching exclusion's reason, or None when applicable."""
    for exclusion in model["exclusions"]:
        if scope not in exclusion.get("scope", ["pairwise", "nightly"]):
            continue
        if _matches(exclusion, values):
            return str(exclusion["reason"])
    return None


def valid_tuples(model: dict[str, Any], scope: str = "pairwise") -> list[dict[str, str]]:
    """Enumerate every non-excluded tuple in stable declaration order."""
    axes = model["axes"]
    if scope == "nightly":
        axis_names = [axis for axis in NIGHTLY_AXES if axis in axes]
    else:
        axis_names = [axis for axis in PAIRWISE_AXES if axis in axes]
    tuples: list[dict[str, str]] = []
    for combination in itertools.product(*(axes[axis] for axis in axis_names)):
        values = {axis: str(value) for axis, value in zip(axis_names, combination, strict=True)}
        if is_excluded(model, values, scope) is None:
            tuples.append(values)
    return tuples


def tuple_id(values: dict[str, str], axes: list[str] | tuple[str, ...] = PAIRWISE_AXES) -> str:
    """Return the deterministic identifier of a tuple."""
    return "::".join(str(values[axis]) for axis in axes)


def pair_keys(
    values: dict[str, str], axes: tuple[str, ...] = PAIRWISE_AXES
) -> set[tuple[str, str]]:
    """Return every axis-value pair carried by one tuple."""
    pairs: set[tuple[str, str]] = set()
    for left, right in AXIS_PAIRS:
        if left in values and right in values:
            pairs.add((f"{left}={values[left]}", f"{right}={values[right]}"))
    return pairs


def required_pairs(model: dict[str, Any]) -> set[tuple[str, str]]:
    """Re-derive every valid pair from the declared domains and exclusions."""
    pairs: set[tuple[str, str]] = set()
    for values in valid_tuples(model, scope="pairwise"):
        pairs |= pair_keys(values)
    return pairs


def rows_of(model: dict[str, Any], tier: str | None = None) -> list[dict[str, Any]]:
    """Return the declared rows, optionally filtered by tier."""
    rows = model["rows"]
    if tier is None:
        return list(rows)
    return [row for row in rows if row.get("tier") == tier]


def row_values(row: dict[str, Any]) -> dict[str, str]:
    """Project one row onto the declared axes."""
    return {axis: str(row[axis]) for axis in PAIRWISE_AXES}


def coverage_problems(model: dict[str, Any]) -> list[str]:
    """Return every missing pair, invalid row or duplicate tuple."""
    problems: list[str] = []
    required = required_pairs(model)
    covered: set[tuple[str, str]] = set()
    seen_tuples: dict[str, str] = {}
    for row in model["rows"]:
        values = row_values(row)
        row_id = str(row["id"])
        reason = is_excluded(model, values, "pairwise")
        if reason is not None:
            problems.append(f"row '{row_id}' is excluded but declared: {reason}")
        identity = tuple_id(values)
        if identity in seen_tuples:
            problems.append(
                f"row '{row_id}' duplicates tuple of '{seen_tuples[identity]}' ({identity})"
            )
        seen_tuples[identity] = row_id
        covered |= pair_keys(values)
    missing = sorted(required - covered)
    for left, right in missing:
        problems.append(f"missing pair: {left} x {right}")
    unknown_ids = {str(row["id"]) for row in model["rows"]}
    for mandatory in pinned_rows():
        if mandatory["id"] not in unknown_ids:
            problems.append(f"mandatory fast row missing: {mandatory['id']}")
    return problems


def _core_values(model: dict[str, Any]) -> set[str]:
    """Return every declared core axis value token."""
    return {f"{axis}={value}" for axis in NIGHTLY_AXES for value in model["axes"][axis]}


def _model_only_values(model: dict[str, Any]) -> set[str]:
    """Return the core values that are declared and proven at model level only."""
    return {f"{entry['axis']}={entry['value']}" for entry in model.get("model_only", [])}


def assign_tiers(
    model: dict[str, Any],
    row_values_list: list[dict[str, str]],
    mandatory_values: list[dict[str, str]] | None = None,
) -> list[str]:
    """Assign deterministic fast/slow tiers to generated rows.

    Mandatory rows are fast. The remaining fast rows greedily cover every
    stage/kind/cookie/position value the mandatory rows do not already carry, so
    the fast tier represents the whole core vocabulary; everything else is slow.
    """
    tiers: list[str] = []
    uncovered = _core_values(model) - _model_only_values(model)
    for mandatory in mandatory_values or []:
        uncovered -= {f"{axis}={mandatory[axis]}" for axis in NIGHTLY_AXES}
    for values in row_values_list:
        carried = {f"{axis}={values[axis]}" for axis in NIGHTLY_AXES}
        if carried & uncovered:
            tiers.append("fast")
            uncovered -= carried
        else:
            tiers.append("slow")
    if uncovered:
        raise ModelError(f"fast tier cannot represent: {sorted(uncovered)}")
    return tiers


def generate_rows(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate a deterministic constrained pairwise covering in stable order.

    ``PRESERVED_FAST`` rows are pre-selected rows: they do not reduce the pair
    requirement, so adding or refreshing a preserved pin can never change which
    rows the greedy pass selects (a reviewed slow row is never silently dropped by
    a tier-only change). ``MANDATORY_FAST`` finding proofs are seeded the same way
    they always were and do reduce the requirement.
    """
    axes = [axis for axis in PAIRWISE_AXES if axis in model["axes"]]
    tuples = valid_tuples(model, scope="pairwise")
    pair_cache = {tuple_id(values): pair_keys(values, tuple(axes)) for values in tuples}
    requirement = set()
    for cache in pair_cache.values():
        requirement |= cache

    mandatory: list[dict[str, Any]] = []
    mandatory_tuples: set[str] = set()
    for entry in MANDATORY_FAST:
        values = {axis: str(entry[axis]) for axis in PAIRWISE_AXES}
        reason = is_excluded(model, values, "pairwise")
        if reason is not None:
            raise ModelError(f"mandatory row '{entry['id']}' is excluded: {reason}")
        mandatory.append({**entry, "tier": "fast"})
        mandatory_tuples.add(tuple_id(values))
        requirement -= pair_keys(values)
    for entry in PRESERVED_FAST:
        values = {axis: str(entry[axis]) for axis in PAIRWISE_AXES}
        reason = is_excluded(model, values, "pairwise")
        if reason is not None:
            raise ModelError(f"preserved fast row '{entry['id']}' is excluded: {reason}")
        mandatory.append({**entry, "tier": "fast"})
        mandatory_tuples.add(tuple_id(values))

    ordered = [tuple_id(values) for values in tuples]
    random.Random(model["seed"]).shuffle(ordered)
    chosen: list[dict[str, str]] = []
    remaining = set(requirement)
    while remaining:
        best_key: str | None = None
        best_gain = 0
        for key in ordered:
            gain = len(pair_cache[key] & remaining)
            if gain > best_gain:
                best_key, best_gain = key, gain
        if best_key is None:
            raise ModelError(f"uncoverable pairs remain: {sorted(remaining)[:5]}")
        chosen.append(next(values for values in tuples if tuple_id(values) == best_key))
        remaining -= pair_cache[best_key]

    generated = [
        {**values, "id": tuple_id(values)}
        for values in chosen
        if tuple_id(values) not in mandatory_tuples
    ]
    tiers = assign_tiers(
        model,
        [{axis: row[axis] for axis in PAIRWISE_AXES} for row in generated],
        [{axis: entry[axis] for axis in PAIRWISE_AXES} for entry in pinned_rows()],
    )
    for row, tier in zip(generated, tiers, strict=True):
        row["tier"] = tier
    rows = mandatory + generated
    rows.sort(key=lambda row: (row["tier"] != "fast", str(row["id"])))
    return rows


def check_file(path: str | Path) -> list[str]:
    """Return every problem in the checked-in covering file (empty means OK)."""
    try:
        model = load_model(path)
    except (ModelError, OSError, json.JSONDecodeError) as err:
        return [f"{path}: {err}"]
    problems = coverage_problems(model)
    core = _core_values(model) - _model_only_values(model)
    fast_values = set()
    for row in rows_of(model, "fast"):
        fast_values |= {f"{axis}={row[axis]}" for axis in NIGHTLY_AXES}
    missing_core = sorted(core - fast_values)
    if missing_core:
        problems.append(f"fast tier does not represent: {missing_core}")
    for entry in model.get("model_only", []):
        token = f"{entry['axis']}={entry['value']}"
        probe = dict.fromkeys(PAIRWISE_AXES, "")
        probe[entry["axis"]] = str(entry["value"])
        if is_excluded(model, probe, "pairwise") is None:
            problems.append(f"model-only value {token} is still executable by the pairwise rows")
        if not any(
            values[entry["axis"]] == str(entry["value"])
            for values in valid_tuples(model, scope="nightly")
        ):
            problems.append(f"model-only value {token} is missing from the nightly declaration")
    for mandatory in pinned_rows():
        matches = [row for row in model["rows"] if row["id"] == mandatory["id"]]
        if matches and matches[0].get("tier") != "fast":
            problems.append(f"mandatory row '{mandatory['id']}' is not fast")
    return problems


def _write_rows(path: Path, model: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    updated = dict(model)
    updated["rows"] = rows
    path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", metavar="FILE", help="verify the checked-in covering")
    group.add_argument("--generate", metavar="FILE", help="print generated rows for the file")
    group.add_argument("--write", metavar="FILE", help="regenerate and rewrite the file's rows")
    args = parser.parse_args(argv)

    if args.check:
        problems = check_file(args.check)
        if problems:
            for problem in problems:
                print(f"FAIL {problem}")
            print(f"{len(problems)} problem(s)")
            return 1
        model = load_model(args.check)
        print(
            f"OK pairs={len(required_pairs(model))} rows={len(model['rows'])} "
            f"fast={len(rows_of(model, 'fast'))} slow={len(rows_of(model, 'slow'))} "
            f"seed={model['seed']}"
        )
        return 0

    try:
        model = load_model(args.generate or args.write)
        rows = generate_rows(model)
    except (ModelError, OSError, json.JSONDecodeError) as err:
        print(f"FAIL {err}")
        return 1
    if args.generate:
        print(json.dumps(rows, indent=2))
        return 0
    _write_rows(Path(args.write), model, rows)
    print(f"wrote {len(rows)} rows to {args.write}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
