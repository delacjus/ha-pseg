# Hourly Statistics: Rollout, Verification and Rollback

Audience: a Home Assistant owner who can install a HACS integration, open
**Settings**, and read entity attributes. No SQL or SSH is needed for the normal
path.

This runbook covers the selective hourly port in version **1.5.0**. It preserves
the existing statistic ids, all daily history and the authentication/keepalive
behaviour. It does **not** claim that PSE&G's real hourly contract has been proven:
the promotion gate exists precisely because the vendor's hourly start/end,
timezone and zero semantics are still unverified.

## What changes

- Recent polls request both an authoritative **daily** chart and an **hourly**
  chart for the same 14-day window.
- A closed New York calendar day is promoted from one daily row to hourly rows only
  when it is complete: exactly the expected 23/24/25 UTC hourly starts, every value
  finite (zero is data), both raw labels carrying an explicit timezone/offset and
  naming `[x, x+1h)`, and the hourly sum agreeing with the daily total within
  rounding tolerance. Date-only or bare wall-clock labels are
  `timestamp_semantics_unverified` and keep the daily fallback.
- The New York-midnight daily row is overwritten by the first hourly value in the
  same statistic id (`pseg:<meter_id>_energy_consumption` /
  `pseg:<meter_id>_energy_cost`). A promoted day is never downgraded by a later
  daily retry.
- Sensor history and `latest_*` values stay authoritative **daily**; hourly rows
  are for statistics and provenance only.
- One pending journal entry covers the complete mutation for **both** series,
  including daily corrections and their re-chained sums. Provenance commits only
  after both series and their cumulative sums are read back. An unfinished mutation
  is replayed idempotently before new work, and an unloaded entry retires its old
  coordinator so it cannot overwrite the new one.
- Manual `pseg.backfill_history` stays daily-only. A daily total that contradicts a
  promoted day is rejected for the whole import before any write, and logged.
- A chart redirect to the anonymous portal home is treated as a mode-specific
  authentication loss, never as a successful daily fallback.
- Cost stays an estimate (`kWh × configured rate`). Daily cost keeps cents; hourly
  cost keeps six decimals so 24 hours do not accumulate cent rounding.
- The connection status sensor shows `statistics_imports_enabled`; the consumption
  sensor shows `statistics_granularity`, `statistics_hourly_complete_days` and
  `statistics_hourly_incomplete_days`.

## Before you start

1. Home Assistant 2024.1 or newer, HACS installed, and the PSE&G entry currently
   **connected**.
2. A recent Home Assistant backup. This integration does not create or restore
   recorder backups; keep using your own backup/export process.
3. Know the statistic ids for the account you are changing. In **Developer Tools** >
   **Statistics**, search for `pseg:` and note the
   `..._energy_consumption` / `..._energy_cost` pair.
4. Do not start while a planned keepalive soak or other maintenance is still
   running.
5. Do not uninstall or downgrade the integration as part of this rollout.

## Rollout (repeatable)

1. In HACS, update **PSE&G Energy (New Jersey)** to **1.5.0** (or install the
   reviewed build). Confirm the manifest shows `1.5.0`.
2. Restart Home Assistant when the maintenance window allows it.
3. Open **Settings** > **Devices & Services** > **PSE&G**. Confirm the entry is
   loaded and the Connection Status sensor reads **Connected**.
4. Open the consumption sensor and record these attributes:
   - `statistics_granularity`
   - `statistics_hourly_complete_days`
   - `statistics_hourly_incomplete_days`
   - `statistics_last_import`
5. Wait for one normal poll (the integration polls every 4 hours) or press the
   **Refresh** button.
6. Open **Settings** > **System** > **Logs**, filter for `pseg`, and read the line
   beginning `PSE&G hourly statistics:`. It reports how many days were promoted and
   the reasons any day was not.
7. Open **Settings** > **Dashboards** > **Energy** and inspect yesterday's
   electricity bars. A promoted day shows hourly detail; an unpromoted day keeps
   the daily total.
8. Confirm the statistic ids did not change. The Energy Dashboard configuration and
   all older history stay attached.

### Expected first result

- **`daily`** is the expected, safe result until the vendor's real hourly payload
  has been observed on an approved deployment. The existing daily statistics are
  imported exactly as before.
- **`mixed`** means some closed days validated and others did not. The reasons in
  the log identify the incomplete days.
- **`hourly`** means every closed day in that poll validated. This is evidence for
  the poll window, not permanent proof of the vendor contract.

## Verify a promoted day

1. In the consumption sensor attributes, confirm `statistics_granularity` is
   `hourly` or `mixed` and `statistics_last_import` is recent.
2. In the log, confirm the promoted count is greater than zero and there is no
   `rejected` line for the same poll.
3. In the Energy Dashboard, compare the day's total with the daily figure shown
   before promotion. The total should be unchanged within rounding; only its
   distribution across hours is new.
4. Check the cost statistic for the same day. Its day delta should be approximately
   `kWh × configured rate`; small differences are expected because the rate is an
   estimate and daily cost is stored in cents.
5. Confirm the day has hourly rows, not a daily row plus hourly rows. The promoted
   midnight row is the first hour's value, not the whole day's total.

### Optional advanced check

Home Assistant owns the recorder schema; it can change between releases. If you are
comfortable with SQLite, stop Home Assistant cleanly first and query a **copy** of
the recorder database. Do not edit the live database. The normal path above is
enough for acceptance.

## Rollback

Hourly statistics are not reversible by reinstalling the old 1.4.2 daily importer:
that importer would append a daily row beside the hourly rows or overwrite the first
hour, double-counting or corrupting the day. Use the supported stop instead.

1. Open **Settings** > **Devices & Services** > **PSE&G** > **Configure**.
2. Turn off **Import Long-Term Statistics** and save.
3. The entry reloads. Confirm the Connection Status sensor still reads **Connected**
   and its `statistics_imports_enabled` attribute is `false`.
4. Automatic, startup-deferred and manual statistics imports now stop. Sign-in, the
   credential-free 3-minute (portal) or 10-minute (Okta) keepalive probe, bounded
   cookie renewal and polling continue.
5. Leave the existing statistics untouched. They remain readable in the Energy
   Dashboard; they are simply no longer updated by this integration.
6. Restoring or editing recorder data is a separate operation. Use a verified
   private backup/export and Home Assistant's supported recorder recovery path. The
   integration does not provide a restore action and does not clear history.
7. To resume later, turn **Import Long-Term Statistics** back on. The next poll runs
   the pending-journal recovery first, then continues normal reconciliation.

### Pending journal

Before any recorder write, the exact rows for both series are saved to
`.storage/pseg.statistics.<entry_id>` and the coordinator waits for that save to
complete. Completion alone is not trusted: the exact snapshot is read back from the
Store path and validated. Recovery refuses to replay an in-memory mutation while a
physical save is outstanding, failed, stale or unreadable; it retries after the
bytes are durable. The journal is
cleared only after both series and their cumulative sums verify. If Home Assistant
stops between the two series or the commit wait times out, the next poll verifies
both series and either commits the provenance or replays the same rows. Do not
delete this file to "fix" a day; a repeated failure is a recorder problem, not a
reason to clear history.

## Troubleshooting

| Symptom | Meaning | Action |
|---|---|---|
| `statistics_granularity: daily` for several polls | The hourly chart was absent, daily-shaped, or did not validate | Keep the daily fallback; do not force hourly. Report sanitized logs if it persists. |
| `granularity_not_hourly` | The payload did not look hourly | Safe fallback; the vendor contract may not be honoured for this account. |
| `missing_hours` | A closed day lacked one or more expected starts | Safe fallback. Check whether the portal published a partial day. |
| `sum_mismatch` | Hourly points did not add up to the daily total | Safe fallback; never force a promotion. |
| `label_mismatch` | A raw label contradicted the UTC hour | Safe fallback; the vendor timestamp semantics need review. |
| `timestamp_semantics_unverified` | Labels were date-only, bare wall-clock, or missing an explicit offset | Safe fallback; do not force hourly until aware start/end labels are observed. |
| `interval_end_mismatch` | An aware end label did not name `x + 1h` | Safe fallback; `x` may be an interval end. |
| `open_day` | Today's New York day is still open | Expected; it promotes on a later poll after midnight. |
| `no_daily_total` | No independent daily total was available | Safe fallback; the hourly rows are not authoritative alone. |
| `rejected before any statistics were written` | A daily total contradicts a promoted day | Nothing was written. Wait for a complete hourly poll, or use the kill switch and a backup. Do not hand-edit statistics. |
| `Recorder did not commit ...` | The commit barrier timed out | The journal stays pending. Check recorder health; the next poll retries. If it repeats, disable imports. |
| `hourly` shows 23 or 25 rows | A DST day | Expected: 23 hours in spring, 25 in fall, always at New York midnights. |

## Limits and guarantees

- The poll window is 14 days. Manual backfill remains daily and can cover up to two
  years.
- Promotion requires an independent daily total; point count alone is never enough.
- Cost is an estimate, never a PSE&G bill. Changing the rate affects future imports;
  it does not rewrite already promoted days through a daily-only retry.
- Portal-reported actual dollar cost (`UsageType: "2"`) is governed by the
  independent portal cost contract in `docs/portal-cost.md`. In v1.7.0, cost evidence
  is non-authoritative and isolated; it does not write to recorder statistics or
  alter the estimated cost series (`_energy_cost`). A zero observation in portal cost
  is valid data and is never replaced by an estimate.
- Statistic ids, metadata and the existing history are preserved. No history clear
  or reset is performed.
- Authentication, CAPTCHA handling and keepalive are unchanged by this migration.
  The separate auth hardening in the same release adds one bounded, cookie-only
  renewal on a typed portal expiry (see the README section "How background renewal
  works"); it never runs from a network error, a 5xx or a maintenance page.
  Its poll/keepalive budget survives ordinary reload and failed startup, and
  malformed budget metadata refuses renewal. A process or disk crash can lose a
  recent best-effort metadata save. Roll back auth alone to reviewed hourly base
  `2285845`, retaining all hourly rows, provenance and the pending journal; never
  restore the 1.4.2 daily importer after hourly writes.
- The vendor's real hourly start/end, timezone and zero semantics remain unverified
  until an approved live poll observes them. A `daily` result is the designed
  fallback, not a bug.
