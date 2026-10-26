# Provenance: `usagetype3_daily_synthetic.json`

## What it was derived from

One browser session capture of the MyMeter dashboard with the chart switched to
**cost / $** and the range set to daily, taken by the repository owner on 2026-10-26
and saved as a `ChartData` response body. That capture is **private**: it lives
outside this repository in a `chmod 600` file, it contains real meter numbers and
real dollar values, and it is **not** in git and never will be. Nothing in this
directory is the capture.

The capture was used only to learn the response **shape**: key names, key order,
nesting, the series list (an unnamed hidden navigator series, two meter columns, a
temperature spline on `yAxis 1`, an `Energy Marker` flags series), the `Data`-level
keys, `tooltipOptions`, and the point field set
`{x, y, hs.start, hs.end, xs, xe, v}` with `xe = x + 86399999` and
`hs.end = hs.start + 1 day`.

## What was replaced

Every value that came from the owner's meter or bill was replaced:

| Field | Replacement |
|---|---|
| Meter numbers in the two series names | `000012345678` and `000087654321` (synthetic 12-digit ids; the service label `(Residential Service (RS))` is a generic plan label) |
| All 15 daily point `y` values | made-up dollar amounts written with the same long-float precision style (one integer digit and ~15 decimals) |
| `Data.maxUsage` / `Data.minUsage` | the maximum and minimum of the synthetic point values, so the block stays self-consistent |
| `Data.maxUsageDate` / `Data.minUsageDate` | the `x` of those synthetic points |
| All dates (`x`, `xs`, `xe`, `hs.start`, `hs.end`, axis ranges) | a synthetic 2026-09-01 .. 2026-09-15 window with the same arithmetic |
| Navigator series (298 points in the capture) | 6 synthetic 2-decimal points, same two-element list form |
| Temperature *series* | 2 synthetic points (first and last of 15) with a synthetic `tr` label |
| `_capture` and `_note` annotation text | rewritten to say this is a synthetic fixture |
| `Energy Marker` | left empty, exactly as observed |

Values kept as observed because they are chart configuration, not owner data:
`colors`, `xAxis`, `chartLastMin/Max`, `useRangeMin/Max`, `rangeSelector`,
`plotOptions`, `yAxis`, `tooltipOptions` (`currency: "USD"`,
`usageTypeDisplayName: "Dollar"`, `storageType: "daily"`, ...), every
`dataGrouping` / `showInLegend` / `visible` / `showHoverChart` / `showMinMax_MM` /
`dateFormatString` / `lineWidth` / `shape` flag, and `usageType: "Dollar"`.

## What is guaranteed

- No real meter number, dollar value, temperature or timestamp from the capture
  appears in this file.
- Structure was checked key-by-key (names, order, nesting, JSON types) against the
  private capture: zero differences. Only list lengths of the truncated series and
  the values differ by design.
- Consumers must treat this file as **synthetic**. It can prove that the parser
  accepts the observed shape; it can never count as an observation of the portal's
  behaviour, a rate, or a bill.
