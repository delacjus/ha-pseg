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
- **Background Renewal**: Uses a domain-scoped cookie jar. With a saved MyMeter login or `MM_RememberMe` cookie, Home Assistant renews the portal session itself and does not use Okta; Okta-only setups renew through standard SAML auto-post flows, with a 10-minute keepalive check. How long unattended renewal keeps working is not verified, and PSE&G can still ask for a CAPTCHA or another human step.
- **Statistics Corruption Fix**: Uses Home Assistant External Statistics (`pseg:<meter_id>_energy_consumption` and `pseg:<meter_id>_energy_cost`) with strict cumulative sum preservation across rolling windows and backfills.
- **Transparent Cost Estimation**: Accurately describes cost calculations as estimates based on a configurable electric rate ($0.247/kWh default), adjustable at any time via integration Options.
- **HA Entity Best Practices**: Removed hardcoded `entity_id` overrides and entity registry hacks. Fully leverages `_attr_has_entity_name` and translation keys.
- **Frontend XSS Protection**: Sanitizes dynamic data and error messages rendered inside `pseg-energy-card`.

## Features

- **Daily Smart Meter Readings**: Captures daily electricity usage (`sensor.pseg_electricity_consumption`).
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
2. Drag the **PSE&G CAPTCHA helper** button from that page onto your bookmarks bar.
   The page contains only instructions and the bookmarklet, never account data.
   Dragging a bookmarklet has not been verified on every browser: the portal's
   page policy may block a `javascript:` bookmark there. A toolbar-extension
   candidate exists for that case, but it is a test candidate only (see
   `docs/captcha-extension-testing.md`), not a shipped or verified browser path.
3. In another tab, open `https://mysmartenergy.nj.pseg.com`, then click the
   bookmarklet once to arm it. It does not sign you in.
4. Click **Sign In**, solve the CAPTCHA yourself, then press **Copy verification**
   in the helper popup that holds the proof the page would have sent. The helper
   stops that one login request so the proof stays unused.
5. Return to the Home Assistant dialog, paste it into the masked **CAPTCHA proof**
   field, and submit. Google's reCAPTCHA response is only valid for about two
   minutes, so capture and paste it promptly; Home Assistant drops the pending
   sign-in after ten minutes without a proof.

The proof is single-use: Home Assistant sends it once, never saves it, and never
reuses it after a timeout or a lost reply. Capture a fresh one instead. You can
press **Cancel this sign-in** in the dialog to drop the attempt.

> **Experimental.** Handing a proof solved in your browser to Home Assistant has
> not been verified against a live PSE&G account yet. PSE&G may bind the proof to
> the browser that solved it and refuse it. If that happens, the dialog asks for a
> fresh proof; re-authenticating in the browser remains the fallback.

A CAPTCHA-assisted sign-in proves the account works *now* and gives the current
access only. It does not create a permanent renewable session, so a later CAPTCHA
prompt needs you again.

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

Entity ids below are for the first configured account (device name `PSEG`). A second account
gets the same ids with a `_2` suffix; point the card's `entity`, `next_update_entity` and
`connection_status_entity` options at those.

- `sensor.pseg_electricity_consumption`: Latest daily electric usage in kWh (contains `history_14d` and daily stats)
- `sensor.pseg_electricity_cost`: Latest daily estimated cost in USD
- `sensor.pseg_meter_id`: Meter serial number / identification
- `sensor.pseg_latest_reading_date`: Date of the most recent recorded reading
- `sensor.pseg_outdoor_temperature`: Recorded low, average, and high temperatures
- `sensor.pseg_next_update`: Timestamp of the next scheduled polling attempt
- `sensor.pseg_connection_status`: Connection status with session telemetry attributes
- `button.pseg_refresh_data`: Button to trigger an immediate portal sync

## License

MIT
