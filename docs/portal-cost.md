# PSE&G Portal Cost Contract and Non-Authoritative Request Seam

This document specifies the technical contract for PSE&G portal dollar data (`UsageType: "3"`,
the value the browser's cost chart sends — see §2.4 for the observed contract),
establishing the boundaries, request parameters, status vocabulary, data quarantine rules, and
evidence requirements for Phase A (v1.7.0 evidence-only capture) and future Phase B (v1.8.0 statistics).

The primary goal of this specification is to freeze the dollar contract and non-authoritative request
seam without altering existing energy consumption (`kWh`) or estimated cost (`kWh × configured rate`)
pipelines.

---

## 1. Overview and Phased Architecture

The integration distinguishes between two distinct cost concepts:
1. **Estimated Electricity Cost (`pseg:<meter>_energy_cost`)**: Computed as `kWh × configured rate`
   (in cents). This series remains intact and continues to provide immediate, continuous cost tracking
   for Home Assistant Energy.
2. **PSE&G Portal-Reported Cost (`pseg:<meter>_energy_cost_actual`)**: Sourced directly from the PSE&G
   portal's billing chart data (`UsageType: "3"`). It is labeled **PSE&G portal-reported cost** until
   comprehensive charge coverage across all bill components is formally verified against real utility bills.

### Rollout Phases
- **Phase A (v1.7.0)**: Isolated, bounded evidence collection only. Cost requests run under an isolated
  session without session confirmation, cookie rotation, or recorder writes. Captured samples are
  exposed strictly through bounded diagnostics (`cost_contract_sample`).
- **Phase B (v1.8.0)**: Introduction of the independent `_energy_cost_actual` Long-Term Statistics (LTS)
  series, a dedicated journal/store, and an administrative cutover tool for Home Assistant Energy.

---

## 2. Request Seam and Form Field Preservation

Portal cost data is requested from the same `/Dashboard/Chart` and `/Dashboard/ChartData` endpoints used
for consumption data, parameterized by `UsageType`.

### 2.1 UsageType Specification
- `UsageType` parameter accepts only two valid string values:
  - `"1"`: Consumption (`kWh`) — default for all existing calls.
  - `"3"`: Cost (`USD` / `$`).
- Validation rules:
  - Default value is `"1"`.
  - Allowed values are strictly `{"1", "3"}`.
  - Any other value (e.g., `"0"`, `"2"`, `"cost"`, `1`, `None`) is rejected with a validation error.

**Correction (v1.7.2): `"2"` → `"3"`.** Releases 1.7.0 and 1.7.1 sent `UsageType: "2"`. That value was
an upstream assumption (`sidprax/ha-pseg`), never observed, and the first live sample it produced proved
no unit at all (`wrong_unit` / `currency_unproven`). The MyMeter dashboard's cost chart was then captured
from the browser (2026-10-26) and it sends `UsageType: "3"` with `jsTargetName: "UsageType"`. The
consumption chart keeps `UsageType: "1"` with `jsTargetName: "StorageType"`, so `jsTargetName` is not a
free-form field: it names the chart control that changed.

### 2.2 Form Field Invariant
The POST to `/Dashboard/Chart` MUST preserve all fourteen canonical form fields (as built today in `custom_components/pseg/pseg_client.py:2217-2232` `_fetch_chart_json` for the daily/hourly poll legs, and `:1895-1910` for backfill chunks; intervals from `custom_components/pseg/const.py` `USAGE_INTERVAL_DAILY`/`USAGE_INTERVAL_HOURLY`). Both consumption builders hard-code `UsageType: "1"` (`:2220`, `:1898`). No field may be omitted,
renamed, or altered when requesting cost data, ensuring identical request construction:

| Field Name | Type | Value / Specification |
|---|---|---|
| `__RequestVerificationToken` | `str` | Antiforgery token from the active `/Dashboard` page |
| `UsageInterval` | `str` | `"6"` for Daily, `"5"` for Hourly |
| `UsageType` | `str` | `"1"` (Consumption) or `"3"` (Cost) |
| `jsTargetName` | `str` | `"StorageType"` (Consumption) or `"UsageType"` (Cost) |
| `EnableHoverChart` | `str` | `"true"` |
| `Start` | `str` | Start date formatted as `YYYY-MM-DD` |
| `End` | `str` | End date formatted as `YYYY-MM-DD` |
| `IsRangeOpen` | `str` | `"False"` |
| `MaintainMaxDate` | `str` | `"true"` |
| `SelectedViaDateRange` | `str` | `"False"` |
| `ChartComparison` | `str` | `"1"` |
| `ChartComparison2` | `str` | `"0"` |
| `ChartComparison3` | `str` | `"0"` |
| `ChartComparison4` | `str` | `"0"` |

### 2.3 Non-Authoritative Transport SeamCost sampling runs under strict isolation within the coordinator poll:
- **Two extra dispatches**: One POST `/Dashboard/Chart` followed by one GET `/Dashboard/ChartData`.
- **Locked sequence**: Executed within the client lock (`_locked`), immediately following the successful
  authoritative daily and hourly consumption fetches.
- **Zero extra authentication**: Never triggers `/Dashboard` navigation, token renewal, login, or SSO keepalive.
- **Isolated session (`AllowlistedSession`)**:
  - Seeded in-memory from the pre-cost authoritative cookie jar.
  - Restricted strictly to portal HTTPS on port 443.
  - Response cookies are discarded: `Set-Cookie` headers are never adopted or propagated.
  - `allow_redirects = False`: Any 30x HTTP response is treated as an immediate evidence rejection.
- **Zero lifecycle side effects**:
  - Never calls `_note_confirmed_generation`, `ensure_session`, or `_mark_auth_failure`.
  - HTTP 401/403 or login page detections on cost requests yield an observational status (`auth_rejected`)
    in evidence mode and do NOT invalidate the authoritative session or disrupt kWh sensor updates.
  - Never writes to recorder statistics or the version-2 statistics store.

### 2.4 Observed Contract (browser capture, 2026-10-26)

Everything in this section was observed from one real session, not assumed. The raw capture is private
(real meter numbers and real dollar values), is stored outside this repository, and is **not** in git. A
synthetic fixture with the same structure lives in
`tests/fixtures/cost_contract/usagetype3_daily_synthetic.json` (see its `PROVENANCE.md`).

**Request** — `POST /Dashboard/Chart`, form-encoded, exactly the fourteen fields of §2.2 with
`UsageType: "3"`, `jsTargetName: "UsageType"` and `UsageInterval: "6"` for the daily chart, followed by
`GET /Dashboard/ChartData`. The daily cost window aligns with the daily kWh window: `x` is the day's
`00:00 UTC`, `hs.start`/`hs.end` are date-only `MM/DD/YYYY` labels with `hs.end` one day after
`hs.start`, `xs == x`, `xe == x + 86399999`, and `v` is `false`.

**Response** — `{"_capture": …, "AjaxResults": [], "Data": {…}}`. `Data` carries `colors`, `series`,
`usageType`, `maxUsageDate`, `maxUsage`, `minUsageDate`, `minUsage`, `xAxis`, `yAxis`, `chartLastMin`,
`chartLastMax`, `useRangeMin`, `useRangeMax`, `rangeSelector`, `plotOptions` and `tooltipOptions`. The
series list is, in order:

| # | Series | Role |
|---|---|---|
| 0 | unnamed, `visible: false`, points as `[x, y]` pairs | hidden navigator: ignore |
| 1 | `Meter #<digits> (…)`, `type: "column"`, `tooltip.valuePrefix: "$"` | authoritative meter |
| 2 | `Meter #<digits> (…)`, `type: "column"` | second meter, may legitimately be empty |
| 3 | `Temperature`, `type: "spline"`, `yAxis: 1` | weather overlay: ignore |
| 4 | `Energy Marker`, `type: "flags"` | event flags: ignore |

Only series matching `_METER_SERIES` (`^\s*Meter #(\d+)`) are evidence, and only when the meter id is in
the authoritative set proven by the kWh leg (§4.2). Point values are parsed as `Decimal` at source
precision; the extra point fields `xs`, `xe` and `v` are dropped and counted, never retained.

**Currency proof.** `UsageType` asks for a chart; it does not guarantee the response is dollars, so the
response must prove it:

- **Proof** (both required):
  - `Data.tooltipOptions.currency == "USD"` — exact and case-sensitive, and
  - `Data.usageType == "Dollar"` **or** `Data.tooltipOptions.usageTypeDisplayName == "Dollar"`.
- **Corroboration only, never sufficient alone**: `Data.yAxis[0].title.text == "$"` and a meter series
  `tooltip.valuePrefix == "$"`. A chart can be labelled `$` and still encode something else; a label is
  not a unit.
- **Contradiction** — any present unit signal that is not dollars rejects the sample as
  `wrong_unit` / `unsupported_unit`: another currency (e.g. `EUR`), a lower-case or otherwise inexact
  currency token, a usage type that is not `Dollar` (e.g. `kWh`), a y-axis title, a legacy unit key or a
  meter-series prefix naming another unit.
- **Nothing present** → `wrong_unit` / `currency_unproven`. Absence is never proof, and this is exactly
  what the first live sample (1.7.0, `UsageType: "2"`) produced.

**Meaning of "real cost" here.** Over the observed window, every daily portal dollar value equalled that
day's kWh multiplied by one constant per-kWh rate — the ratio was stable to the 2-decimal precision of the
kWh values, and no fixed charge, delivery charge, rider, tax or net-metering adjustment appeared. So the
portal's "Dollar" series is the **energy-supply charge at the portal's rate**, not the customer's bill.
It remains labelled **PSE&G portal-reported cost**; full-bill coverage stays unproven (§7.1).

**Hourly cost is still unproven.** The hourly slot keeps `UsageInterval: "5"` and the same `UsageType: "3"`
payload, but nothing observed says the portal publishes hourly dollars. It may `HOLD`; daily acceptance
never carries over (see `v1.8.0` gates in §8.4).

---

## 3. Status Vocabulary

All cost evidence evaluations produce a distinct, typed status code:

| Status Code | Description | Condition / Cause |
|---|---|---|
| `missing` | Cost payload or series absent | Response is empty, `Data` key is missing, or `series` list is empty |
| `malformed` | Unparseable or corrupt payload | Invalid JSON, non-dict point structures, or unexpected payload types |
| `unsupported` | Unsupported endpoint or flow | Portal returned HTTP 30x redirect, or account lacks cost chart feature |
| `auth_rejected` | Authentication rejected | HTTP 401, 403, or login page detected on the cost request |
| `wrong_meter` | Meter identity mismatch | Series meter ID does not match the authoritative kWh meter, or attempts to discover/enlarge meters |
| `wrong_unit` | Incompatible unit of measure | Dollars are not proven (`currency_unproven`), or a present unit signal contradicts them (`unsupported_unit`: another currency, a non-`Dollar` usage type, a non-`$` axis title or meter-series prefix) |
| `budget_exhausted` | Sampling budget spent | The durable 1-attempt/day sampling permit was already spent |
| `truncated` | Data exceeded safety bounds | Total points > 1,500, series > 4, or payload size > 256 KiB |
| `ok` / `valid` | Healthy cost evidence | All structural, identity, and numeric constraints satisfied |

---

## 4. Meter Matching vs Upstream Rejection

Upstream commit `63c912f` introduced permissive meter selection logic:
```python
# UPSTREAM FLAW (63c912f) - DO NOT IMPLEMENT:
c_meter = next((s for s in c_series if "Meter" in str(s.get("name") or "")), None)
if not c_meter and c_series:
    c_meter = c_series[0]
```

### 4.1 Upstream Flaws
1. **Arbitrary first-series fallback (`series[0]`)**: Accounts with multiple meter records (e.g., an inactive
   replaced meter or previous-year comparisons) can list the inactive meter first. Selecting `series[0]`
   binds the cost series to an obsolete or 0-point meter.
2. **First-nonempty heuristic**: Indiscriminately picks the first series with "Meter" in its label without
   verifying whether it matches the active contributing meter.
3. **Identity enlargement**: Cost requests have no authority to discover or expand the set of known meters.

### 4.2 Authoritative Identity Matching Contract
- Cost series MUST be matched strictly against the authoritative meter set (`_expected_meter_ids` /
  `meter_ids`) proven by the authoritative consumption (`kWh`) leg.
- Each candidate series is parsed using `_METER_SERIES` (`^\s*Meter #(\d+)`).
- If a series meter ID is not in the authoritative set, it is rejected with status `wrong_meter`.
- When an account lists multiple meters (e.g., inactive old meter with 0 points followed by active meter
  with 312 points), the validator matches by identity. Meter reordering or inactive series never lead
  to misattribution.

---

## 5. Numeric Observations and Quarantine Rules

Upstream commit `63c912f` introduced a zero-to-estimate substitution:
```python
# UPSTREAM FLAW (63c912f) - DO NOT IMPLEMENT:
if actual_hourly_cost is not None and actual_hourly_cost > 0:
    cost_val = actual_hourly_cost
else:
    cost_val = round(p_kwh * effective_rate, 4)
```

### 5.1 Zero is a Valid Observation
- A reported cost value of `$0.00` (`y == 0.0` or `y == 0`) is a valid numeric observation.
- Legitimate zero-cost intervals occur during net-metered solar export hours, off-peak periods, or
  minimum-charge threshold intervals.
- **Rule**: A zero observation must NEVER be treated as missing data and must NEVER be replaced by an
  estimated rate calculation (`kwh * rate`).

### 5.2 Quarantine Policy
Any data point violating structural or mathematical validity is quarantined:
- **Booleans**: `True` and `False` (which evaluate as `int` in Python) are quarantined as `malformed`.
- **Non-finite numbers**: `NaN`, `+Infinity`, and `-Infinity` are quarantined as `malformed`.
- **Negative values / credits**: Points with `y < 0` are quarantined until credit/billing adjustments
  are explicitly supported and verified.
- **Duplicate timestamps or dates**: Multiple points sharing identical `x` timestamps or date keys
  are quarantined as `malformed`.
- **Unknown currencies**: dollars must be proven from the response (§2.4); a payload that proves nothing is
  `currency_unproven`, and any present token that contradicts dollars is `unsupported_unit`.

---

## 6. Bounded Sample Diagnostics Contract

To allow offline validation without risking memory exhaustion or credential leakage, cost samples
in `cost_contract_sample` diagnostics adhere to strict limits:
- **Maximum series**: 4 meter series.
- **Maximum data points**: 1,500 points total across all series.
- **Maximum sample slots**: 2 slots (e.g., latest daily and latest hourly).
- **Maximum serialized size**: 256 KiB total JSON output. Any truncation flags evidence as non-promotable (`truncated`).
- **Privacy guarantees**:
  - No antiforgery tokens, session cookies, passwords, or Okta credentials.
  - Meter numbers are mapped to stable anonymized placeholders (e.g., `Meter #1`).
  - No raw HTML, response headers, or unparsed diagnostic dumps.
- **Zero-request diagnostics**: Downloading the diagnostics JSON generates zero network requests to the portal.

---

## 7. Inventory of UNKNOWN Facts

The following facts cannot be deduced from consumption (`UsageType: "1"`) data or upstream assumptions.
They remain explicitly **UNKNOWN** until observed across live, verified samples:

1. **Full-Bill Charge Coverage**:
   - *Unknown*: Does the portal dollar series include delivery charges, customer fixed charges, state riders,
     clean energy taxes, and solar net-metering credits, or does it reflect only energy supply charges?
   - *Requirement*: Label remains **PSE&G portal-reported cost** until a user-provided redacted bill
     proves line-item equivalence over an entire billing cycle. The observed window (§2.4) showed no
     charge of any kind beyond kWh × the portal's flat per-kWh rate, so fixed/rider/tax coverage is not
     merely unverified — it was absent for the days captured.
2. **Hourly Cost Availability**:
   - *Unknown*: Does PSE&G publish hourly cost points (`UsageInterval: "5"`, `UsageType: "3"`) for all
     residential smart-meter customers, or is cost restricted to daily aggregates (`UsageInterval: "6"`)?
   - *Requirement*: Daily and hourly evidence gates remain decoupled. Hourly cost is not assumed to exist
     simply because hourly kWh exists.
3. **Cost Timestamp Semantics (`UsageType: "3"`)**:
   - *Unknown*: Does an hourly cost point timestamp `x` represent America/New_York wall-clock hour START
     encoded as UTC ms (as proven for UsageType 1), or interval END, or true UTC? Daily cost points are
     observed on day `00:00 UTC` with date-only `hs` labels (§2.4); that says nothing about hourly points.
   - *Requirement*: UsageType 1 timestamp proof (KB `5e0c2b1a-7f3d-4a91-9c2e-20261025a001`) must NOT be
     blindly imported. Independent hourly sum and start-alignment checks are required.
4. **Rounding Quantum and Precision**:
   - *Unknown*: Does the portal report `y` in cents (2 decimal places) or sub-cent precision (4 decimal places)?
     How are daily totals rounded relative to hourly point sums?
   - *Requirement*: Precision-derived cent conservation rules must be calibrated against observed samples
     before any statistics backfill.
5. **Restatement and Publication Lag**:
   - *Unknown*: What is the publication lag of cost data relative to kWh data? Do earlier days restate
     when utility billing windows close?
   - *Requirement*: Multi-day observation (>48h repeat snapshots) must verify whether past days remain stable.
6. **Daylight Saving Time (DST) Transitions**:
   - *Unknown*: How does the portal represent the 23-hour spring and 25-hour fall ambiguous wall-clock hour
     for dollar series?
   - *Requirement*: Fall-back transitions (e.g., Nov 1) must be observed rather than synthesized.

---

## 8. v1.7.0 Release Scope — Evidence Only

Release 1.7.0 is the first release that talks to the portal cost chart, using the
then-assumed `UsageType: "2"`; **1.7.2 corrects it to `"3"`, the value the browser's
cost chart sends (§2.1, §2.4)**, and proves dollars from the response instead of
assuming them. Its scope is deliberately narrow: **collect bounded evidence,
change nothing else**. This section is the operator-facing summary; the request
seam, status vocabulary, identity rules, numeric quarantine and sample bounds are
defined in sections 2–6 above.

### 8.1 What the release adds

| Surface | Contract |
|---|---|
| Bounded sampler | At most **one cost request pair per entry per New York day** (one `POST /Dashboard/Chart` plus one `GET /Dashboard/ChartData`), executed **after** the healthy daily and hourly kWh legs, inside the same `_locked` client sequence, on an ordinary current-owner coordinator poll only. |
| Isolation | A short-lived `AllowlistedSession` seeded in memory from the authoritative jar, narrowed to the portal HTTPS host/port, `allow_redirects=False`, every response cookie rejected, at most 1 MiB streamed, whole-pair deadline enforced, closed on every exit. It cannot call `ensure_session`, note a confirmed generation, mark an auth failure or persist a checkpoint. |
| Budget | Reserved durably in a separate auth-free evidence store **before** dispatch; one-use permit; alternates daily and hourly slots on successive days; reload/restart/manual refresh cannot reset or bypass it. Corrupt budget state skips sampling. |
| Control | Admin action `pseg.set_cost_mode` with `cost_mode: off` (default) or `evidence`. `import` exists in the schema as reserved and is **refused** in 1.7.0. Mode changes do not reset budgets, sign in, refresh, reload or touch Energy. |
| Diagnostics | Bounded `cost_contract_sample`: ≤ 4 meter series, ≤ 1,500 points, 2 slots, ≤ 256 KiB serialized. Any truncation marks the slot `truncated`/non-promotable. |
| Statistics | **No change.** No `_energy_cost_actual` series, no Energy preference edit, no recorder write, no change to the version-2 statistics store or the legacy replay suffix routing. |

### 8.2 What is collected (and what never is)

Collected, per slot: sample version, capture time, request window/interval/type,
a safe status and reason code, the unit token, matched series placeholders
(`Meter #<placeholder>`), per-point `x`, `y` as canonical numeric **text** at the
source precision, date labels from `hs.start`/`hs.end`, a point count and a
dropped-field count. Plus, from the same poll, the **paired kWh anchors**: daily
`{date, kwh}` and hourly `{start, kwh}` entries, their counts and a truncated
SHA-256 digest of the sorted contributing meter ids.

Never collected or retained: HTML, response headers, cookies, antiforgery
tokens, arbitrary unknown key names or string values, extra point fields,
exception text, meter serial numbers, account labels, or any bill content. A
sample is bounded sanitization of data the poll already fetched — it is not a
telemetry cache, it is not written to disk, and it is lost on restart by design
(the reserved budget survives).

Downloading diagnostics sends **zero** portal requests.

### 8.3 Turning it on and off

Default is `off`: no sampling, no extra traffic, no budget spent.

```yaml
action: pseg.set_cost_mode
data:
  cost_mode: evidence
```

Turn it off again when you have the captures you need:

```yaml
action: pseg.set_cost_mode
data:
  cost_mode: off
```

`off` stops new sampling and preserves everything already captured, including the
budget state; it is not a reset and it does not authorise clearing anything.

### 8.4 Reading the evidence

The capture and offline review procedure — export diagnostics, build one snapshot
per capture, wait at least 48 hours, run the checker, read the verdict, turn the
mode off — is documented in
`~/ai-tools/docs/pseg-cost-evidence-capture.md`. The checker
(`~/ai-tools/scripts/pseg-cost-contract-check.py`) applies these gates and prints
only verdicts, counts, ranges and fixed reason codes:

- at least **7 overlapping closed days**;
- a **repeated daily snapshot at least 48 hours later**, so a restated past day is
  visible;
- daily dollars vs the **configured-rate estimate** (absolute/relative delta,
  effective rate) — informative, never proof of a richer tariff;
- **matching meter sets and dates** against the kWh side;
- **USD demonstrated**, not assumed;
- **raw precision and the day-rounding quantum** derived from the artifact, with
  equality at the published cent and at most one proven rounding quantum — never
  a relative tolerance;
- **zero / zero-kWh-nonzero-cost / credit days** counted, never estimated;
- **hourly timestamp hypotheses** (New York wall-clock start vs true UTC vs
  hour-end) scored against the anchors, plus **hourly dollars vs portal daily
  dollars**;
- **first-available delay** of cost relative to kWh.

A missing gate is a **HOLD for that granularity**, never an estimated number. The
tool reports `authorizes_import: false` on every run, and a synthetic artifact can
never be counted as an observation.

### 8.5 What v1.7.0 does not claim

- It does not import portal cost and does not change what the Energy dashboard
  shows; cost remains `kWh × configured rate` until 1.8.0.
- It does not claim the portal total equals the bill. Charge coverage stays
  unverified until a reviewed comparison against a user-supplied, redacted bill
  over the exact service period exists (excluding prior balance, payments,
  deposits and other fuels).
- A passing evidence report is a candidate contract for the *observed* window; a
  week does not prove the absence of later billing-period restatement, and the
  real November DST fall-back encoding remains unobserved until it happens.
