# PSE&G Energy (New Jersey) — Home Assistant Integration

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Validate with hassfest](https://github.com/delacjus/ha-pseg/actions/workflows/hassfest.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/hassfest.yaml)
[![HACS Action](https://github.com/delacjus/ha-pseg/actions/workflows/hacs.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/hacs.yaml)
[![Tests](https://github.com/delacjus/ha-pseg/actions/workflows/tests.yaml/badge.svg)](https://github.com/delacjus/ha-pseg/actions/workflows/tests.yaml)

Home Assistant integration for Public Service Electric and Gas (PSE&G) customers in New Jersey. Retrieves daily electric meter readings, costs, and historical energy trends directly from the PSE&G MySmartEnergy portal (MyMeter).

Includes a built-in Lovelace card with 7-day and 14-day history views and kWh / cost switching.

![PSEG Energy Card](docs/card.png)

## Fork Differences (Crestwood Hardening)

This fork (`delacjus/ha-pseg`, forked from `sidprax/ha-pseg`) hardens the integration for security, long-term stability, and "log in once" usability:

- **Security Hardening**: Completely eliminated the insecure companion add-on, stored plaintext passwords, and hard-coded fallback URLs. All credentials stay in the browser.
- **Strict Host Allowlist**: Every HTTP request, redirect, and form submission is strictly restricted to `{mysmartenergy.nj.pseg.com, id.myaccount.pseg.com}`.
- **Log In Once (SAML SSO Renewal)**: Uses a domain-scoped cookie jar. The integration automatically renews portal sessions in the background using your Okta session via standard SAML auto-post flows, with a 30-minute keepalive check.
- **Statistics Corruption Fix**: Uses Home Assistant External Statistics (`pseg:<meter_id>_energy_consumption` and `pseg:<meter_id>_energy_cost`) with strict cumulative sum preservation across rolling windows and backfills.
- **Transparent Cost Estimation**: Accurately describes cost calculations as estimates based on a configurable electric rate ($0.247/kWh default), adjustable at any time via integration Options.
- **HA Entity Best Practices**: Removed hardcoded `entity_id` overrides and entity registry hacks. Fully leverages `_attr_has_entity_name` and translation keys.
- **Frontend XSS Protection**: Sanitizes dynamic data and error messages rendered inside `pseg-energy-card`.

## Features

- **Daily Smart Meter Readings**: Captures daily electricity usage (`sensor.pseg_electricity_consumption`).
- **Cost Estimation**: Estimates daily electricity costs in USD (`sensor.pseg_electricity_cost_estimated`).
- **Home Assistant Energy Dashboard**: External Long-Term Statistics (LTS) support for both consumption and cost.
- **Historical Backfill**: Built-in action (`pseg.backfill_history`) to backfill up to 2 years of historical daily usage and cost directly into Home Assistant Energy statistics.
- **Configurable Rate**: Set your estimated electricity rate ($/kWh) in integration Options.
- **Outdoor Temperature**: Records daily low, average, and high temperatures reported alongside meter readings (`sensor.pseg_outdoor_temperature`).
- **14-Day History**: Provides 14 days of interval usage and cost data in entity state attributes for local charting.
- **Manual Refresh**: Includes a refresh button (`button.pseg_refresh_data`) to trigger an immediate data fetch.
- **Session Telemetry**: Monitors Okta session lifespan and SSO renewal metrics directly on the Connection Status sensor.
- **Built-in Lovelace Card**: Bundles `pseg-energy-card` ready to add from the card picker.

## How to Get Your Session Cookies ("Log In Once")

You log into PSE&G **once** in your browser, copy your session cookies, and the integration maintains the session automatically.

### Chrome / Edge:
1. In your browser, go to `https://id.myaccount.pseg.com` or `https://mysmartenergy.nj.pseg.com` and log in. Check **"Remember me"** or **"Keep me signed in"** if offered.
2. Press **F12** (or right-click anywhere and choose **Inspect**) to open Developer Tools.
3. Switch to the **Network** tab and refresh the page (**F5**).
4. Filter by `id.myaccount.pseg.com` and click on any network request made to that domain (for example, `/app/...` or `introspect`).
5. In the **Headers** pane on the right, find **Request Headers**.
6. Find the **`Cookie:`** line, right-click its value, and select **Copy value**.
7. In Home Assistant, paste this into the **Okta Cookies** field.
8. *(Optional)* Click any request to `mysmartenergy.nj.pseg.com` (such as `/Dashboard`), copy its `Cookie:` header value, and paste it into **Portal Cookies**.

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
3. Paste your **Okta Cookies** and optional **Portal Cookies**.
4. Click **Submit**.

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
| `show_next_update` | boolean | `false` | Display the next scheduled fetch timestamp beside the meter label |
| `popup_hash` | string | `null` | URL hash to open a custom popup card on tap. When omitted, tapping opens standard entity dialog. |

## Entities Provided

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
