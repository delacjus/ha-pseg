# HVAC calibration check

An HVAC energy estimate uses assumed power values. This read-only check compares hourly grid meter energy with climate history to estimate the actual electricity used in each HVAC mode. It subtracts other top-level devices in your Energy dashboard and fits the remaining energy to an idle house load and the time spent in each mode. Results are estimates: other untracked loads can affect them.

## What you need

- Python 3.11 or newer on any computer that can reach Home Assistant, or the Home Assistant Terminal & SSH add-on.
- An hourly grid energy statistic in your Energy dashboard, such as the hourly data from this integration.
- A climate entity with `hvac_action` history. Ecobee `equipment_running` history can distinguish a heat pump from auxiliary heat.
- Several hours of recorded heating and cooling (and any other mode you want to measure), with variation between modes.
- A Home Assistant long-lived access token. Create one in your Home Assistant profile under **Security**. Keep it private.

## Run the check

Download this repository and run from its directory. Set `HA_URL` to your Home Assistant address and `HA_TOKEN` to your token in your shell's environment; alternatively, omit the token and enter it at the prompt. Then run:

```sh
python3 tools/hvac_calibration_check.py --hours
```

If you have multiple climate entities, add `--climate climate.example`. If the grid statistic is not in Energy preferences, specify it with `--grid-stat STAT`; repeat that option for multiple grid imports. Use `--hvac-stat sensor.example` for an existing HVAC estimate to compare its implied watts. Set a period with `--start` and `--end` ISO dates or times. `--help` lists all options.

## Read and apply the results

The output reports the fitted idle house load, measured watts and uncertainty for each mode, and suggested values. A singular fit means the available mode runtimes do not vary enough to separate their effects. Large uncertainty or negative watts indicate the data do not support a reliable value. Review the suggested values and enter suitable values in your own HVAC estimate helper or configuration; this tool does not change it.

Other large loads can add noise. Run the check again after collecting more heating and cooling hours. History recorded before a change keeps its old values. The tool only reads Home Assistant data.
