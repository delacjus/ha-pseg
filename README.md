# PSE&G Energy (New Jersey) — Home Assistant Integration

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Validate with hassfest](https://github.com/delacjus/ha-pseg/actions/workflows/hassfest.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/hassfest.yaml)
[![HACS Action](https://github.com/delacjus/ha-pseg/actions/workflows/hacs.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/hacs.yaml)
[![Tests](https://github.com/delacjus/ha-pseg/actions/workflows/tests.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/tests.yaml)

Home Assistant integration for Public Service Electric and Gas (PSE&G) customers in New Jersey. Retrieves daily electric meter readings, costs, and historical energy trends directly from the PSE&G MySmartEnergy portal (MyMeter).

Includes a built-in Lovelace card with 7-day and 14-day history views and kWh / cost switching. The card loads automatically into Home Assistant dashboards since release 1.6.1.

![PSEG Energy Card](docs/card.png)

## About This Fork (`delacjus/ha-pseg`)

This project (`delacjus/ha-pseg`) is an independent fork of `sidprax/ha-pseg`. It hardens the integration for security, authentication reliability, and long-term statistics integrity:

- **Direct local MyMeter sign-in**: Home Assistant signs into MyMeter directly. There is no companion add-on, and credentials are never sent over HTTP to a `localhost:8000` helper.
- **Strict host allowlist**: Every HTTP request, redirect, and form submission is strictly restricted to `{mysmartenergy.nj.pseg.com, id.myaccount.pseg.com}`. When signing in with a MyMeter email and password, requests are narrowed to `mysmartenergy.nj.pseg.com` only, preventing any credentials or tokens from being sent to Okta.
- **Bounded cookie-only keepalive**: The integration runs a credential-free `GET /Dashboard` check every 3 minutes. If the session has lapsed, this timer performs a bounded cookie renewal (at most 2 attempts per cookie generation, spaced at least 15 minutes apart) and verifies access with a read-only meter check before saving cookies. Regular data polling can fall back to submitting the saved MyMeter email and password when the renewal policy permits it; the keepalive timer never submits them.
- **Diagnostics redaction**: Diagnostic downloads automatically redact email addresses, passwords, session cookies, and meter serial numbers.
- **Stable statistics with correction guards**: Uses Home Assistant External Statistics (`pseg:<meter_id>_energy_consumption` and `pseg:<meter_id>_energy_cost`) with strict cumulative sum preservation across rolling windows and backfills. Gaps are preserved and existing data is never wiped out.
- **Hourly statistics**: Live since release 1.6.0. Promotes complete recent days to hourly resolution while safely falling back to daily rows when data is incomplete.

### Upstream Synchronization

From upstream `sidprax/ha-pseg`, this fork has adopted:
- **Official PSE&G logos** (upstream 1.0.4): High-resolution `icon.png` and `logo.png` assets.
- **Automatic card loading** (upstream 1.0.1): Automatically registers `pseg-energy-card` with Home Assistant dashboards upon startup.
- **MyMeter invited-user setup steps** (upstream 1.1.0 README): How to create the direct MyMeter email login this fork signs in with (see Configuration).

This fork deliberately does **not** adopt:
- **Companion auth server**: Upstream transmits plaintext credentials over unencrypted HTTP to a local helper server. This fork communicates directly with PSE&G over encrypted HTTPS.
- **Mixed cost statistic**: Upstream (1.0.2) mixes portal-reported dollars with a rate-based estimate inside one cost statistic, and derives a floating 7-day average rate. This fork keeps its cost statistic a stable configured-rate estimate until real portal cost has been verified, and will then add real cost as a **separate** series (see the cost roadmap below).
- **Auth-type menu and pasted MyMeter cookies** (upstream 1.1.0): The new "Direct MyMeter" sign-in options either send your password to the companion add-on, or ask you to paste a browser `MM_SID` cookie. This fork already signs in to MyMeter directly with renewal, and its testing found browser-exported cookies often fail outside the browser.
- **OptionsFlow update listeners** (upstream 1.0.3): The fork already uses `OptionsFlowWithReload` to reload configuration cleanly on save without update listener races.

## Features

- **Daily Smart Meter Readings**: Captures daily electricity usage in kWh (`sensor.pseg_electricity_consumption`).
- **Hourly Statistics**: Live since release 1.6.0. Automatically promotes complete days to hourly External Statistics with strict validation guards.
- **Cost Estimation**: Estimates daily electricity costs in USD (`sensor.pseg_electricity_cost`) using your configured $/kWh rate.
- **Home Assistant Energy Dashboard**: Native External Long-Term Statistics (LTS) support for both consumption and cost.
- **Historical Backfill**: Built-in action (`pseg.backfill_history`) to backfill up to 2 years of historical daily usage and cost into Home Assistant Energy statistics.
- **Configurable Rate**: Set your estimated electricity rate ($/kWh) in integration Options at any time.
- **Outdoor Temperature**: Records daily low, average, and high temperatures reported alongside meter readings (`sensor.pseg_outdoor_temperature`).
- **14-Day History**: Provides 14 days of interval usage and cost data in entity state attributes for local charting.
- **Manual Refresh**: Includes a refresh button (`button.pseg_refresh_data`) to trigger an immediate portal sync.
- **Session Telemetry**: Monitors session lifespan and renewal status directly on the Connection Status sensor (`sensor.pseg_connection_status`).
- **Built-in Lovelace Card**: Bundles `pseg-energy-card`, auto-registered and ready to add to any dashboard since 1.6.1.
- **Portal cost evidence (opt-in, v1.7.0)**: A bounded, isolated capture of the PSE&G portal's dollar chart, exposed only through diagnostics and controlled by the admin action `pseg.set_cost_mode`, which is **off by default**. It imports nothing: costs are still estimated from your configured rate until real portal cost has been verified.

## Installation

Requires **Home Assistant 2026.10.2 or newer**, the minimum version tested by this project. Earlier releases are not supported.

### Via HACS (Recommended)

[![Open your Home Assistant instance and open this repository inside HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=delacjus&repository=ha-pseg&category=integration)

Click the button above to open this repository in HACS on your own Home Assistant (it adds the custom repository for you), then click **Download** and restart Home Assistant. Or add it by hand:

Install `delacjus/ha-pseg` as a custom repository in HACS:

1. In Home Assistant, navigate to **HACS** > **Integrations**.
2. Click the three dots (top right) and select **Custom repositories**.
3. In the **Repository** field, enter:
   ```text
   https://github.com/delacjus/ha-pseg
   ```
4. Set the **Category** to **Integration** and click **Add**.
5. Find **PSE&G Energy (New Jersey)** in the integrations list.
6. Click **Download**, select the latest release (**1.7.0** or newer), and click **Download**.
7. Restart Home Assistant.

> **Note**: Do not search for or install the default upstream listing (`sidprax/ha-pseg`). This fork must be added as a custom repository using the URL above.

### Manual Installation

1. Download the latest release from [GitHub Releases](https://github.com/delacjus/ha-pseg/releases).
2. Copy the `custom_components/pseg` directory into your Home Assistant `config/custom_components/` folder.
3. Restart Home Assistant.

## Configuration

[![Open your Home Assistant instance and start setting up PSE&G Energy.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=pseg)

After installing and restarting, click the button above to start setup directly, or:

1. In Home Assistant, go to **Settings** > **Devices & Services** > **Add Integration**.
2. Search for **PSE&G Energy (New Jersey)**.
3. Enter your MyMeter **Email** and **Password** (the login credentials from `https://mysmartenergy.nj.pseg.com`).
4. Click **Submit**.

### Getting a MyMeter email login

Most PSE&G customers only have the "Sign in Via My Account" (Okta) login, which this integration does not use. To get a direct MyMeter email and password, invite a second user to your own meter. These steps are adapted from upstream 1.1.0's README:

1. Sign in to your PSE&G account at [pseg.com](https://www.pseg.com) and open **MySmartEnergy (MyMeter)**.
2. In the top menu, click **Connect User / Share Access**.
3. Enter an email address you control, such as a secondary address or an alias like `yourname+pseg@gmail.com`.
4. Select your electric meter, choose access with **No end date**, and send the invitation.
5. Open the invitation email, follow the link, and choose a password and security question.

Use that invited email and password in step 3 above. Signing in this way never asks for an SMS or email code.

Home Assistant stores your credentials and session cookies in the integration config entry and uses them to authenticate directly with MyMeter over HTTPS. The integration does not encrypt these stored values itself; protect access to your Home Assistant configuration and backups.

## Signing In and the CAPTCHA Helper Extension

The recommended login method uses your MyMeter email and password directly on `https://mysmartenergy.nj.pseg.com`. These credentials are separate from PSE&G's "Sign in Via My Account" button (which routes through Okta with two-factor SMS/email). Home Assistant signs in directly through MyMeter and never follows redirects to Okta.

### Solving CAPTCHAs with the Browser Extension

MyMeter protects logins with an invisible reCAPTCHA. Home Assistant cannot solve CAPTCHAs automatically. When PSE&G presents a challenge, Home Assistant pauses and asks you to capture a verification token using a lightweight browser helper extension.

The extension consists of three files in `custom_components/pseg/frontend/`:
- `manifest.json`: Manifest V3 configuration.
- `service-worker.js`: Background script that activates only when you click the toolbar icon.
- `pseg-captcha-helper.js`: Injected script that holds the verification token on the page.

*(Note: `pseg-energy-card.js` also resides in the frontend folder for dashboard display, but it is not part of the extension).*

**Security and permissions:**
- The extension requests only `activeTab` and `scripting` permissions.
- It has no host permissions, runs no background network requests, and stores no data.
- It only acts when you explicitly click its toolbar button, and only on `https://mysmartenergy.nj.pseg.com`.

#### Step 1: Obtain the Extension ZIP

You can download the helper extension ZIP in either of two ways:
1. **From your Home Assistant instance**: Navigate to `<your-ha-url>/api/pseg/captcha-helper` in a desktop browser and click **Download helper extension (ZIP)**.
2. **From GitHub Releases**: Download `pseg-captcha-helper-extension.zip` directly from the latest [GitHub Release](https://github.com/delacjus/ha-pseg/releases). A matching `.sha256` checksum file is provided to verify file integrity.

#### Step 2: Install the Extension in Chrome or Edge

1. Extract the downloaded ZIP file into a dedicated folder on your computer.
2. Open your desktop browser and go to `chrome://extensions` (in Google Chrome) or `edge://extensions` (in Microsoft Edge).
3. Enable **Developer mode** (toggle switch in the top right or left).
4. Click **Load unpacked** and select the folder where you extracted the extension.
5. Pin the "PSE&G verification helper" icon to your browser toolbar for easy access.

#### Step 3: Capture the Verification Proof

1. In a new tab, open `https://mysmartenergy.nj.pseg.com`.
2. Click the helper extension button in your toolbar. The panel in the bottom-right corner will show **Ready**.
3. Click the MyMeter **Sign In** button and solve the CAPTCHA challenge in your browser.
4. While active, the helper intentionally holds the response and pauses the website's login request so the token remains unspent.
5. When the helper panel displays **Verification captured**, click **Copy verification**.
6. Switch back to the Home Assistant setup dialog, paste the token into the masked **CAPTCHA proof** field, and click **Submit**.
7. Click **Close helper** in the browser panel (or reload the tab) to restore normal portal behavior.

> **Important Caveats:**
> - The helper extension requires a desktop browser (Chrome or Edge).
> - Google reCAPTCHA tokens expire in approximately 2 minutes; copy and submit the token promptly.
> - A CAPTCHA-assisted sign-in verifies your session for current access; it does not guarantee permanent unattended access. PSE&G may periodically request another security check or CAPTCHA.

### How Background Renewal Works

Once signed in, Home Assistant maintains the session in the background:
1. **Keepalive probe**: Every 3 minutes, Home Assistant sends a credential-free `GET /Dashboard` request to check if the session is alive.
2. **Cookie renewal**: If the portal prompts for a renewed session and a `MM_RememberMe` cookie is present, Home Assistant requests a refreshed session cookie without re-sending your password. Renewals are bounded to at most 2 attempts per cookie generation, spaced at least 15 minutes apart, and verified with a read-only meter reading before being saved.
3. **Re-authentication prompt**: If a session expires completely, or if PSE&G demands a new CAPTCHA or security question, automatic attempts stop safely. Home Assistant alerts you to re-authenticate rather than risking account lockout.

The regular data poll has a separate saved-password fallback when the renewal policy permits it. A poll that encounters an expired session may submit your saved MyMeter email and password over HTTPS. CAPTCHA/security-step latches and an exhausted renewal generation block that fallback; the three-minute keepalive always remains cookie-only.

### Older Authentication Methods

The integration retains backward-compatible support for legacy login methods:
- **Okta cookies**: Paste cookies obtained after signing in via "Sign in Via My Account". These sessions expire after approximately one hour and require periodic manual pasting.
- **MyMeter cookie paste (`MM_RememberMe`)**: Browser-exported `MM_RememberMe` cookies often fail outside the browser. If rejected, Home Assistant prompts for your MyMeter email and password.

## Hourly and Daily Statistics

Hourly statistics are **live since release 1.6.0**:

- **New York Wall-Clock Starts**: Hourly data points from PSE&G represent `America/New_York` wall-clock hour starts (verified against portal CSV exports and official daily totals).
- **Strict Date Validation**: An hourly interval is accepted only when both interval boundary labels strictly match `MM/DD/YYYY` format with matching local dates.
- **Daily Total Guard**: A completed day is promoted from daily to hourly statistics only when the sum of its hourly readings matches the independently reported daily total within rounding tolerance.
- **DST Handling**: Daylight Saving Time transitions are handled strictly according to New York local time. Spring-forward days have 23 hourly intervals. Fall-back days (such as November 1, 2026) remain recorded as daily totals by design to prevent ambiguous local hour collisions.
- **Sensor Attributes**: The consumption sensor exposes `statistics_granularity` (`hourly`, `mixed`, or `daily`), `statistics_hourly_complete_days`, and `statistics_hourly_incomplete_days`.

For detailed architecture and verification procedures, see [Hourly Statistics Documentation](docs/hourly-statistics.md).

## Home Assistant Energy Dashboard

The integration imports external long-term statistics for both electricity consumption and cost:

1. In Home Assistant, navigate to **Settings** > **Dashboards** > **Energy**.
2. Under **Electricity Grid**, click **Add Consumption**.
3. Select your PSE&G meter consumption statistic (`pseg:<meter_id>_energy_consumption`).
4. Select **Use an existing statistic with total energy costs** and choose `pseg:<meter_id>_energy_cost`.
5. Click **Save**.

The Energy Dashboard will reflect your electricity consumption and estimated costs.

### Cost Estimation and Roadmap

- **Estimated Cost Today**: The current cost entity (`sensor.pseg_electricity_cost`) and statistics series (`pseg:<meter_id>_energy_cost`) calculate costs as an estimate: `kWh × configured rate` (set in integration Options, defaulting to $0.247/kWh).
- **Roadmap (Real PSE&G Cost)**:
  - **Release 1.7.0**: Portal-reported dollar **evidence only**, off by default. Enabling `pseg.set_cost_mode` with `cost_mode: evidence` lets the integration sample the portal cost chart at most once per day and expose it as a bounded `cost_contract_sample` in diagnostics. Nothing is imported, no statistics change, and the Energy dashboard still shows your estimated cost.
  - **Release 1.8.0 (Planned)**: A separate actual-cost statistics series (`pseg:<meter_id>_energy_cost_actual`) with a dedicated toggle for the Energy Dashboard. It ships only after the captured evidence has been reviewed.

#### What v1.7.0 does not do

- It does not write portal dollars into any statistic and does not switch your Energy dashboard to them.
- It does not claim the portal total equals your bill. Charge coverage (delivery, fixed charges, taxes, credits) stays unverified until a reviewed bill comparison exists.
- It does not collect data on its own: sampling happens during a normal scheduled poll, at most once per New York day, inside the existing locked request sequence. A diagnostics download triggers zero portal requests.

See [Portal Cost Contract](docs/portal-cost.md) for the request seam, the bounded sample shape, the privacy limits and the evidence gates.

## Lovelace Card

The `pseg-energy-card` bundles with the integration and **auto-loads automatically since release 1.6.1**. No manual Lovelace resource registration is needed (existing manual resource entries are harmless and do not conflict).

The card displays only its configured entity. Home Assistant retains previous readings during connection failures; the card does not store account data in browser storage. Loading the updated card removes the older shared browser cache. If your entity has a legacy name, use that exact entity ID in the card configuration.

Add the card to any dashboard:

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
| `connection_status_entity` | string | `sensor.pseg_connection_status` | Connection status entity; shows re-authentication banner when `auth_required` |
| `show_next_update` | boolean | `false` | Display next scheduled fetch timestamp beside the meter label |
| `popup_hash` | string | `null` | URL hash to open a custom popup card on tap. When omitted, tapping opens standard entity dialog. |

## Stopping Statistics Imports (Rollback)

After hourly data exists, reinstalling the legacy 1.4.2 daily importer is **not** supported: it would corrupt or double-count days. To stop statistics imports safely:

1. Open **Settings** > **Devices & Services** > **PSE&G** > **Configure**.
2. Turn off **Import Long-Term Statistics** and click **Save**.
3. The entry automatically reloads. Authentication keepalives and entity sensors continue updating, while automatic and manual statistics imports stop cleanly.

To resume imports at any time, re-enable the option in the same menu.

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

The backfill action operates at daily resolution and preserves existing hourly days. If **Import Long-Term Statistics** is disabled, the action exits immediately without contacting the portal.

## Entities Provided

Entities created for the registered meter account:

- `sensor.pseg_electricity_consumption`: Latest daily electric usage in kWh (includes `history_14d`, `statistics_granularity`, and hourly completeness attributes)
- `sensor.pseg_electricity_cost`: Latest daily estimated cost in USD
- `sensor.pseg_meter_id`: Meter serial number / identification
- `sensor.pseg_latest_reading_date`: Date of the most recent recorded reading
- `sensor.pseg_outdoor_temperature`: Recorded low, average, and high temperatures
- `sensor.pseg_next_update`: Timestamp of the next scheduled polling attempt
- `sensor.pseg_connection_status`: Connection status with session telemetry attributes
- `button.pseg_refresh_data`: Button to trigger an immediate portal sync

## HVAC calibration check

Most HVAC energy estimates in Home Assistant multiply runtime by a guessed wattage. `tools/hvac_calibration_check.py` checks that guess against your real hourly grid meter (for example this integration's hourly PSE&G data). It subtracts your other Energy dashboard devices, then measures the watts your system actually draws while heating, cooling or running the fan, and shows what your current estimate assumes.

It is a single read-only Python 3.11+ file with no dependencies; it never changes Home Assistant. Quick start:

```sh
curl -O https://raw.githubusercontent.com/delacjus/ha-pseg/main/tools/hvac_calibration_check.py
HA_URL=http://homeassistant.local:8123 python3 hvac_calibration_check.py --hvac-stat sensor.your_hvac_energy
```

Paste a long-lived access token at the hidden prompt. See the [HVAC calibration guide](docs/hvac-calibration.md) for requirements, reading the results and applying them.

## Testing

The integration maintains a comprehensive test suite covering authentication lifecycles, parser contracts, hourly statistics invariants, and copy-only mutation testing.

- **Automated CI**: GitHub Actions runs `test (3.14)` (fast pytest suite and ruff linting), `node` (Node 22 offline suite), and `hassfest`.
- **Local Testing**: Run the complete local test suite in disposable snapshots:
  ```sh
  # from the repository root, with a Python 3.14 environment that has requirements_test.txt installed
  python -B tools/release_check.py all --source . --python "$(command -v python)"
  ```
  The `all` profile runs `fast`, `node`, `independent`, and `mutation` suites in isolated temporary directories.

For complete testing details, see [Testing Documentation](docs/testing.md).

## License

MIT
