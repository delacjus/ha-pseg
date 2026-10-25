# PSE&G Portal Cost Contract and Non-Authoritative Request Seam

This document specifies the technical contract for PSE&G portal dollar data (`UsageType: "2"`),
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
   portal's billing chart data (`UsageType: "2"`). It is labeled **PSE&G portal-reported cost** until
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
  - `"2"`: Cost (`USD` / `$`).
- Validation rules:
  - Default value is `"1"`.
  - Allowed values are strictly `{"1", "2"}`.
  - Any other value (e.g., `"0"`, `"3"`, `"cost"`, `1`, `None`) is rejected with a validation error.

### 2.2 Form Field Invariant
The POST to `/Dashboard/Chart` MUST preserve all fourteen canonical form fields (as built today in `custom_components/pseg/pseg_client.py:2217-2232` `_fetch_chart_json` for the daily/hourly poll legs, and `:1895-1910` for backfill chunks; intervals from `custom_components/pseg/const.py` `USAGE_INTERVAL_DAILY`/`USAGE_INTERVAL_HOURLY`). Both builders hard-code `UsageType: "1"` (`:2220`, `:1898`). No field may be omitted,
renamed, or altered when requesting cost data, ensuring identical request construction:

| Field Name | Type | Value / Specification |
|---|---|---|
| `__RequestVerificationToken` | `str` | Antiforgery token from the active `/Dashboard` page |
| `UsageInterval` | `str` | `"6"` for Daily, `"5"` for Hourly |
| `UsageType` | `str` | `"1"` (Consumption) or `"2"` (Cost) |
| `jsTargetName` | `str` | `"StorageType"` |
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

### 2.3 Non-Authoritative Transport Seam
Cost sampling runs under strict isolation within the coordinator poll:
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
| `wrong_unit` | Incompatible unit of measure | Unit token is present and not `USD` or `$` (e.g., `EUR`, `kWh`) |
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
- **Unknown currencies**: Any unit token other than `USD` or `$` is flagged as `wrong_unit`.

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
     proves line-item equivalence over an entire billing cycle.
2. **Hourly Cost Availability**:
   - *Unknown*: Does PSE&G publish hourly cost points (`UsageInterval: "5"`, `UsageType: "2"`) for all
     residential smart-meter customers, or is cost restricted to daily aggregates (`UsageInterval: "6"`)?
   - *Requirement*: Daily and hourly evidence gates remain decoupled. Hourly cost is not assumed to exist
     simply because hourly kWh exists.
3. **UsageType 2 Timestamp Semantics**:
   - *Unknown*: Does point timestamp `x` represent America/New_York wall-clock hour START encoded as UTC ms
     (as proven for UsageType 1), or interval END, or true UTC?
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
