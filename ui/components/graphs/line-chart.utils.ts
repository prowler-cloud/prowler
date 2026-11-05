const Y_AXIS_TICK_FORMATTER = new Intl.NumberFormat("en-US", {
  notation: "compact",
  maximumFractionDigits: 1,
});

export function formatYAxisTick(value: number) {
  return Y_AXIS_TICK_FORMATTER.format(value);
}
