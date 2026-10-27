# HVAC calibration check

This read-only check compares an HVAC energy estimate with your hourly grid
meter. It estimates the watts used in each heating or cooling mode using your
climate history and subtracts other devices in your Energy dashboard.

## What you need

- Python 3.11 or newer on a computer that can reach Home Assistant.
- Hourly grid energy data in your Energy dashboard and a climate entity with
  recorded `hvac_action` history. Ecobee `equipment_running` history can also
  distinguish a heat pump from auxiliary heat.
- Several hours of varied heating or cooling history for each mode to measure.

## Get the tool and token

Download the single file (it uses only Python's standard library):

```sh
curl -O https://raw.githubusercontent.com/delacjus/ha-pseg/main/tools/hvac_calibration_check.py
```

Alternatively, clone this repository and use the file in `tools/`.

In Home Assistant, open **Profile → Security → Long-lived access tokens →
Create**. Keep the token private.

## Run it

From the directory containing the downloaded file, replace the example sensor
with your HVAC energy statistic and run:

```sh
HA_URL=http://homeassistant.local:8123 python3 hvac_calibration_check.py --hvac-stat sensor.your_hvac_energy
```

Paste your token at the hidden prompt; it will not appear in shell history.
For scripts, you can supply the token in the `HA_TOKEN` environment variable.
If you cloned the repository, run `python3 tools/hvac_calibration_check.py`
instead. Use `--climate climate.example` if you have multiple climate
entities, or `--grid-stat STAT` if the grid statistic is not in Energy
preferences. `--help` lists all options.

Example output (numbers are illustrative):

```text
Idle house load: 180 W; R²: 0.950
heat: 90 W ± 20 W (3.10 hours); your estimate implies 500 W
Suggested values: heat 90 W
```

If your estimate is a template sensor with watts for each `hvac_action`,
replace the watt number for that mode with the suggested value. Check your
configuration and reload it as appropriate. History before the change keeps
its old values; the tool does not change your configuration.

Other untracked loads can affect the result. Negative values or large
uncertainty need more data, as does a message that there is not enough varied
data. Collect more hours and run the check again before applying a value.
