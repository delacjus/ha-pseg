# PSE&G Energy (New Jersey) — Home Assistant Integration

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Validate with hassfest](https://github.com/delacjus/ha-pseg/actions/workflows/hassfest.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/hassfest.yaml)
[![HACS Action](https://github.com/delacjus/ha-pseg/actions/workflows/hacs.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/hacs.yaml)
[![Tests](https://github.com/delacjus/ha-pseg/actions/workflows/tests.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/tests.yaml)

Home Assistant integration for Public Service Electric and Gas (PSE&G) customers in New Jersey. Retrieves daily electric meter readings, costs, and historical energy trends directly from the PSE&G MySmartEnergy portal (MyMeter).

Includes a built-in Lovelace card with 7-day and 14-day history views and kWh / cost switching.

![PSEG Energy Card](docs/card.png)

## Fork Differences (Crestwood Hardening)

This fork (`delacjus/ha-pseg`, forked from `sidprax/ha-pseg`) hardens the integration for security and long-term stability:

- **Security Hardening**: This fork does not ship or support the upstream companion add-on; that path is removed here, and the integration talks to PSE&G directly. Hard-coded fallback URLs are gone. The MyMeter email/password you enter is stored in this integration's config entry so Home Assistant can sign in with it — it does not stay in the browser.
- **Strict Host Allowlist**: Every HTTP request, redirect, and form submission is strictly restricted to `{mysmartenergy.nj.pseg.com, id.myaccount.pseg.com}`. With a saved MyMeter email/password, the client is narrowed further to `mysmartenergy.nj.pseg.com` only, so local sign-in never sends anything to Okta.
- **Background Renewal**: Uses a domain-scoped cookie jar. With a saved MyMeter login or `MM_RememberMe` cookie, Home Assistant renews the portal session itself and does not use Okta. The 3-minute background check for those portal-only sessions is a credential-free `GET /Dashboard` probe, not a sign-in. Only when that probe is answered with the sign-in page does a bounded, cookie-only renewal run: MyMeter re-issues its session cookie, at most twice per `MM_RememberMe` generation and at least 15 minutes apart, and the result is kept only after a read-only meter check. Network errors, 5xx answers and maintenance pages never start a renewal. Okta-only setups renew through standard SAML auto-post flows, with a 10-minute keepalive check. PSE&G does not document how long a portal session lasts; one observed lapse (~9 minutes without an accepted request) is not a vendor contract. When MyMeter asks for a CAPTCHA, security question or password change, automatic sign-in stops until you re-authenticate: the integration never posts the saved password from the background timer. Renewal reduces re-prompts; it is not a promise of a permanent session.
- **Statistics Corruption Fix**: Uses Home Assistant External Statistics (`pseg:<meter_id>_energy_consumption` and `pseg:<meter_id>_energy_cost`) with strict cumulative sum preservation across rolling windows and backfills.
- **Hourly Statistics with a Daily Gate**: Recent closed New York days are promoted to hourly External Statistics only when all 23/24/25 expected hours are present and their sum agrees with the independently fetched daily total. Incomplete days keep their current daily row.
- **Transparent Cost Estimation**: Accurately describes cost calculations as estimates based on a configurable electric rate ($0.247/kWh default), adjustable at any time via integration Options.
- **Statistics Kill Switch**: One option stops automatic, deferred and manual statistics imports while sign-in and keepalive keep running.
- **HA Entity Best Practices**: Removed hardcoded `entity_id` overrides and entity registry hacks. Fully leverages `_attr_has_entity_name` and translation keys.
- **Frontend XSS Protection**: Sanitizes dynamic data and error messages rendered inside `pseg-energy-card`.

## Features

- **Daily Smart Meter Readings**: Captures daily electricity usage (`sensor.pseg_electricity_consumption`).
- **Hourly Statistics**: Promotes complete recent days to hourly External Statistics, with an explicit daily fallback and per-day provenance.
- **Cost Estimation**: Estimates daily electricity costs in USD (`sensor.pseg_electricity_cost`).
- **Home Assistant Energy Dashboard**: External Long-Term Statistics (LTS) support for both consumption and cost.
- **Historical Backfill**: Built-in action (`pseg.backfill_history`) to backfill up to 2 years of historical daily usage and cost directly into Home Assistant Energy statistics.
- **Configurable Rate**: Set your estimated electricity rate ($/kWh) in integration Options.
- **Outdoor Temperature**: Records daily low, average, and high temperatures reported alongside meter readings (`sensor.pseg_outdoor_temperature`).
- **14-Day History**: Provides 14 days of interval usage and cost data in entity state attributes for local charting.
- **Manual Refresh**: Includes a refresh button (`button.pseg_refresh_data`) to trigger an immediate data fetch.
- **Session Telemetry**: Monitors session lifespan and renewal metrics (including SAML SSO renewals for the legacy Okta path) directly on the Connection Status sensor.
- **Built-in Lovelace Card**: Bundles `pseg-energy-card` ready to add from the card picker.

## Signing In: Your MyMeter Email and Password (non-Okta)

The recommended way is to let Home Assistant sign in for you with a MyMeter
email/password. MyMeter is the portal at `https://mysmartenergy.nj.pseg.com`; its
**Email** and **Password** boxes are a separate login from the "Sign in Via My
Account" button (that one is PSE&G's Okta account). This is the non-Okta route:
Home Assistant never sends that saved login through Okta, so Okta's SMS/email
two-factor prompt is not used. It does **not** promise that PSE&G will never ask
for another security check (for example a CAPTCHA, or a password change on the
MyMeter account); those still have to be answered by you. If MyMeter answers the
email/password sign-in with a redirect to Okta, Home Assistant refuses to follow
it rather than silently signing in through Okta.

1. Open `https://mysmartenergy.nj.pseg.com` and create (or use) a MyMeter login in
   the **Email** / **Password** boxes on that page.
2. Use a password you don't use anywhere else. Home Assistant has to store it in
   its config so it can sign in for you.
3. In Home Assistant, add the integration and enter that same email and password.
   Home Assistant stores that login in the integration's config and uses it for
   MyMeter's own sign-in whenever the portal session ends. How long that keeps
   working unattended is not verified: PSE&G can still ask for another check, for
   example a CAPTCHA, and the dialog then asks you.

If MyMeter ever asks for a captcha, a security question, or a password change, Home
Assistant cannot answer that. Instead of retrying (which could lock the account),
it shows a **Re-authenticate** prompt. Answer the question in your browser, then
submit the Home Assistant prompt with the boxes left empty: it retries the saved
login. A CAPTCHA is handled by the dedicated step below.

### If PSE&G asks for a CAPTCHA

MyMeter's login is protected by an invisible reCAPTCHA. You solve it in your own
browser; Home Assistant never asks you for the proof until it actually needs one.

1. In the Home Assistant dialog, note the helper address it shows
   (`<your-home-assistant>/api/pseg/captcha-helper`) and open it in a **desktop**
   browser.
2. On that page, download the helper extension ZIP and extract it. The ZIP
   contains exactly `manifest.json`, `service-worker.js` and
   `pseg-captcha-helper.js`; the page and the ZIP are public and static.
3. Open `chrome://extensions` (or `edge://extensions`), enable **Developer
   mode**, choose **Load unpacked**, and select the extracted folder. Pin
   "PSE&G verification helper" if you like.
4. In another tab, open `https://mysmartenergy.nj.pseg.com`, click the helper's
   toolbar button (the panel shows **Ready**), then click **Login** and solve
   the CAPTCHA yourself. While active, the helper blocks the portal's own sign-in
   request so the proof stays unused.
5. If the panel says **Verification captured**, the portal staying on its sign-in
   screen is expected: the helper is holding the proof for Home Assistant.
   If it still says **Ready**, nothing has been captured yet. Press **Copy
   verification** in the panel, then return to the Home Assistant dialog, paste it
   into the masked **CAPTCHA proof** field, and submit. Google's reCAPTCHA response
   is only valid for about two minutes, so capture and paste it promptly; Home
   Assistant drops the pending sign-in after ten minutes without a proof. **Close
   helper** (or reloading the tab) removes the panel and restores the portal's
   login.

When a local MyMeter sign-in succeeds for an account already in Home Assistant,
the Add integration dialog updates that entry's saved sign-in. It confirms
**The saved sign-in for this PSE&G account was updated.** An existing disabled
entry stays disabled; its energy history and settings are preserved.

The proof is single-use: Home Assistant sends it once, never saves it, and never
reuses it after a timeout or a lost reply. Capture a fresh one instead. You can
press **Cancel this sign-in** in the dialog to drop the attempt.

The helper page also keeps the older bookmarklet as an explicitly unverified
fallback. The portal's page policy may block a `javascript:` bookmark, so prefer
the extension (see `docs/captcha-extension-testing.md`).

> **Experimental.** The extension has been seen showing **Ready** and closing
> cleanly on one desktop browser (browser name/version not recorded); that is not
> browser acceptance. Handing a proof solved in your browser to Home Assistant has
> not been verified against a live PSE&G account, and other browsers, portability
> and unattended renewal are unverified. PSE&G may still refuse a proof solved
> elsewhere than Home Assistant; the reason is not known yet. If that happens, the
> dialog asks for a fresh proof; re-authenticating in the browser remains the
> fallback.

A CAPTCHA-assisted sign-in proves the account works *now* and gives the current
access only. It does not create a permanent renewable session, so a later CAPTCHA
prompt needs you again.

### How background renewal works

Three different things can happen, and they have different limits:

1. **A keepalive probe** — every 3 minutes for a portal-only session, a
   credential-free `GET /Dashboard`. It only checks whether the portal still
   accepts the session; it never signs in, posts a password or contacts Okta.
2. **A confirmed cookie renewal** — only when that probe lands on the sign-in page
   *and* the jar holds `MM_RememberMe`: Home Assistant asks the portal to re-issue
   its own session cookie (no email/password, no Okta, no CAPTCHA solving). The
   result is published only if a short read-only daily chart read still shows this
   entry's meter; otherwise the previous cookies and telemetry are restored. A jar
   that passed that proof is saved even when a later read in the same poll fails,
   and a later failed response's own `Set-Cookie` is never saved as if the renewal
   had issued it. The product limit is two attempts per cookie generation (one
   initial attempt and one retry after a *transient* failure), at least 15 minutes
   apart, including across generations. A refused cookie, a CAPTCHA demand or a
   security step ends that generation until the cookie is replaced or you sign in
   again.
3. **Human re-authentication** — required when the cookie is unusable, a CAPTCHA
   appears, or PSE&G asks for a security step or password change. Completing the
   prompt starts a fresh renewal generation; it does not reset the 15-minute gap.
   A CAPTCHA or security step met by an automatic attempt is remembered across an
   ordinary reload, a failed startup and a process restart; it stops every later
   automatic sign-in and cookie renewal until a confirmed sign-in clears it.

These limits are not a TTL. PSE&G publishes neither the portal session lifetime nor
the `MM_RememberMe` lifetime, and an anonymous sign-in response cannot distinguish
an expired cookie from a dropped one, a revoked one, or a vendor-side fault. So the
integration acts only on the typed sign-in response and never assumes a fixed
number of minutes.

Polling, background checks and an ordinary integration reload share one renewal
budget. A failed startup also keeps its spent attempt and any terminal refusal;
reloading cannot retry the same refused cookie. Only an actual transient failure
earns the second attempt. A successful renewal with an unchanged Remember Me
cookie, an unfinished request or an unknown outcome earns no retry. While an
earned retry is still inside its 15-minute window and no saved sign-in is
available, the poll reports an ordinary transient wait: Home Assistant keeps
retrying for it instead of stopping the poll schedule and asking you to sign in
again. A settled generation that has no retry left asks for sign-in immediately,
even inside that window. A normal dashboard response that merely re-issues the
Remember Me cookie is not a new generation; only a cookie replaced during a
verified renewal, or a completed sign-in, restarts the generation.

The budget contains only an attempt count, a timestamp, a fixed terminal reason
and a retry flag. Invalid stored budget data stops automatic cookie renewal;
complete the normal re-authentication prompt to repair it. Do not delete the
budget to force another attempt. Home Assistant saves the budget with the
confirmed cookie jar in the same entry update, so a reload cannot pair a rearmed
budget with a replaced cookie. A renewal-verified jar, a spent attempt, and a
CAPTCHA or security step seen by an automatic attempt survive an ordinary reload
or failed startup; an abrupt process or disk failure can still lose a recent save,
so crash durability is best effort. Only a completed sign-in clears the terminal
step. The diagnostic `has_remember_me` field reports presence as a boolean only.

For maintainers, the offline regression and guard-removal checks are documented in
[`docs/auth-review-verification.md`](docs/auth-review-verification.md). To roll back
only this auth change, use reviewed hourly base `2285845` and retain every hourly
statistics row, provenance record and pending journal. Do not reinstall 1.4.2.

### Older methods

Both still work, but they are worse:

- **Okta cookies** ("Sign in Via My Account"). PSE&G's Okta session has no "keep me
  signed in" and ends about an hour after login, so the cookies need re-pasting
  hourly.
- **MyMeter cookie paste** (`MM_RememberMe`). PSE&G issues this cookie to your
  browser, and pasted copies have stopped working outside it in practice; if a
  pasted copy is refused, the dialog asks for the MyMeter email/password instead.

## Installation

### Via HACS (Recommended)

1. In Home Assistant, open **HACS** > **Integrations**.
2. Click the three dots in the top right and select **Custom repositories**.
3. Add the repository:
   ```text
   https://github.com/delacjus/ha-pseg
   ```
4. Set category to **Integration** and click **Add**.
5. Find **PSE&G Energy (New Jersey)**, click **Download**, and restart Home Assistant.

### Manual Installation

1. Copy the `custom_components/pseg` directory to your Home Assistant `config/custom_components/` folder.
2. Restart Home Assistant.

## Configuration

1. In Home Assistant, go to **Settings** > **Devices & Services** > **Add Integration**.
2. Search for **PSE&G Energy (New Jersey)**.
3. Enter your MyMeter **Email** and **Password** (the ones from
   `https://mysmartenergy.nj.pseg.com`).
4. Click **Submit**.

Home Assistant signs in with that login whenever the portal session ends and renews
in the background. How long unattended renewal keeps working is not verified, and
PSE&G can still ask for a CAPTCHA or security step. The optional **Okta Cookies**
and **Portal Cookies** boxes are only for the older methods above.

## Home Assistant Energy Dashboard

The integration imports external long-term statistics for both electricity consumption and cost:

1. In Home Assistant, navigate to **Settings** > **Dashboards** > **Energy**.
2. Under **Electricity Grid**, click **Add Consumption**.
3. Select your PSE&G meter consumption statistic (`pseg:<meter_id>_energy_consumption`).
4. Select **Use an existing statistic with total energy costs** and choose `pseg:<meter_id>_energy_cost`.
5. Click **Save**.

The Energy Dashboard will reflect daily consumption and costs seamlessly.

### Hourly and daily statistics

Recent usage is requested at hourly resolution on each poll, but the integration
keeps the existing daily rows unless an hourly day can be proven complete. PSE&G's
real hourly start/end and zero semantics are not yet verified against a live
account, so the rules are deliberately conservative:

- A day is a **New York calendar day** (America/New_York), never the Home Assistant
  host time zone. A normal day has 24 expected UTC hourly starts; the spring DST
  day has 23 and the fall DST day 25.
- A closed day is promoted only when it has **exactly** those starts, every value is
  finite (an explicit zero counts as data), **both** raw labels carry an explicit
  timezone/offset and name `[x, x+1h)`, and its sum matches the separately fetched
  **daily** total within rounding tolerance. Date-only or bare wall-clock labels are
  `timestamp_semantics_unverified`; they never promote. Point count alone never
  promotes a day.
- The first hourly value overwrites the existing New York-midnight daily row in the
  same statistic id; the rest of the day is replaced by its full hourly set. An
  incomplete or sparse day keeps its stored contribution unchanged.
- `pseg.backfill_history` remains daily-only. A daily retry of an already promoted
  day keeps the hourly rows. If a daily total contradicts a promoted day and no
  complete hourly replacement is available, the whole import is rejected **before
  any write** and logged; nothing is silently skipped.
- The journal is written durably before any recorder write. The exact snapshot is
  read back from the Store path, because Home Assistant's Store can swallow a real
  write error. While a physical save is outstanding, failed, stale or unreadable,
  recovery refuses rather than replaying in-memory state; it retries after the bytes
  persist. A chart login redirect is an authentication
  failure, not a daily fallback.
- Cost remains an estimate: `kWh × configured rate`. Hourly cost states keep six
  decimals, so a day of hours never accumulates cent rounding. The Energy Dashboard
  cost is still an estimate, not a bill.
- Sensor history and `latest_*` values remain the authoritative **daily** series;
  hourly rows are used only for long-term statistics and provenance. A promoted
  day never changes the values the card or daily sensors show.

The consumption sensor reports `statistics_granularity` (`hourly`, `mixed` or
`daily`), `statistics_hourly_complete_days` and `statistics_hourly_incomplete_days`
for the last poll. Until the first normal poll after an approved deployment proves
the vendor's hourly contract, `daily` is the expected, safe result. See
[`docs/hourly-statistics.md`](docs/hourly-statistics.md) for the full migration,
verification and rollback runbook.

## Stopping Statistics Imports (Rollback)

After hourly data exists, reinstalling the old 1.4.2 daily importer is **not** a
safe rollback: it would add a daily row beside the hourly rows or overwrite the
first hour, double-counting or corrupting the day. The supported stop is the
integration option:

1. Open **Settings** > **Devices & Services** > **PSE&G** > **Configure**.
2. Turn off **Import Long-Term Statistics** and save.
3. The entry reloads. Sign-in, cookie renewal and the keepalive continue; automatic,
   startup-deferred and manual statistics imports stop.

The choice is stored in the config entry and survives restarts. Restoring recorder
data is outside this integration: export it first with your own recorder/statistics
backup. Never clear statistics or run a history reset as a rollback.

## Historical Backfill

To backfill historical usage data from the PSE&G portal into Home Assistant Long-Term Statistics:

1. In Home Assistant, navigate to **Developer Tools** > **Actions** (or **Services**).
2. Select the `pseg.backfill_history` action.
3. *(Optional)* Provide a `start_date` and `end_date` (format: `YYYY-MM-DD`). Defaults to 2 years ago if omitted.
4. Click **Perform action**.

Example action YAML:

```yaml
action: pseg.backfill_history
data:
  start_date: "2024-01-01"
  end_date: "2026-10-19"
```

The backfill action stays daily. It uses the same reconciliation as the poll: older
and newer stored rows are re-chained, gaps are kept, and an existing promoted hourly
day is never downgraded. If the requested daily range contradicts a promoted day and
there is no complete hourly replacement, the action logs an explicit rejection and
writes nothing for that entry. While **Import Long-Term Statistics** is off, the
action returns `0` without contacting the portal.

## Lovelace Card

The integration registers `pseg-energy-card` automatically. Add it to any dashboard:

```yaml
type: custom:pseg-energy-card
entity: sensor.pseg_electricity_consumption
```

### Card Options

| Option | Type | Default | Description |
|---|---|---|---|
| `entity` | string | `sensor.pseg_electricity_consumption` | Primary consumption entity |
| `toggle_entity` | string | `input_boolean.pseg_display_dollars` | Optional helper entity to switch between kWh and dollar view |
| `range_toggle_entity` | string | `input_boolean.pseg_chart_14d` | Optional helper entity to switch between 7-day and 14-day chart view |
| `cost_per_kwh` | number | `0.247` | Override effective rate in card calculations |
| `next_update_entity` | string | `sensor.pseg_next_update` | Entity holding the next scheduled fetch timestamp |
| `connection_status_entity` | string | `sensor.pseg_connection_status` | Connection status entity; the card shows the re-authenticate banner when it reads `auth_required` |
| `show_next_update` | boolean | `false` | Display the next scheduled fetch timestamp beside the meter label |
| `popup_hash` | string | `null` | URL hash to open a custom popup card on tap. When omitted, tapping opens standard entity dialog. |

## Entities Provided

Entity ids below are for the first registered account in Home Assistant's entity registry (device name `PSEG`). When multiple accounts are present, Home Assistant may initialize entries concurrently on first load, so whichever account registers its entities first receives the base ids and a second account gets the `_2` suffix; once registered, entity ids remain stable across restarts and each account's entities stay uniquely bound to its config entry. Point the card's `entity`, `next_update_entity` and `connection_status_entity` options at the account's registered entity ids.

- `sensor.pseg_electricity_consumption`: Latest daily electric usage in kWh (contains `history_14d`, `statistics_granularity`, and hourly completeness attributes)
- `sensor.pseg_electricity_cost`: Latest daily estimated cost in USD
- `sensor.pseg_meter_id`: Meter serial number / identification
- `sensor.pseg_latest_reading_date`: Date of the most recent recorded reading
- `sensor.pseg_outdoor_temperature`: Recorded low, average, and high temperatures
- `sensor.pseg_next_update`: Timestamp of the next scheduled polling attempt
- `sensor.pseg_connection_status`: Connection status with session telemetry attributes
- `button.pseg_refresh_data`: Button to trigger an immediate portal sync

## Testing

The integration includes a test suite covering authentication lifecycles, hourly statistics, parser contracts, offline guards, and copy-only mutation testing.

Run local release check profiles using the test environment:

```sh
export PSEG_TEST_PYTHON=/home/tacoriffic/ha-pseg/.venv/bin/python
export PYTHONDONTWRITEBYTECODE=1 RUFF_NO_CACHE=true
"$PSEG_TEST_PYTHON" tools/release_check.py fast --source . --python "$PSEG_TEST_PYTHON"
"$PSEG_TEST_PYTHON" tools/release_check.py node --source . --python "$PSEG_TEST_PYTHON"
```

For the complete testing workflow—including `independent`, `mutation`, and `all` profiles, snapshot verification, and test markers—see [Testing Documentation](docs/testing.md).

## License

MIT
