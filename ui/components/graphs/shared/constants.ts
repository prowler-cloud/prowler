export const SEVERITY_COLORS = {
  Informational: "var(--chart-info)",
  Info: "var(--chart-info)",
  Low: "var(--chart-warning)",
  Medium: "var(--chart-warning-emphasis)",
  High: "var(--chart-danger)",
  Critical: "var(--chart-danger-emphasis)",
} as const;

export const PROVIDER_COLORS = {
  AWS: "var(--chart-provider-aws)",
  Azure: "var(--chart-provider-azure)",
  Google: "var(--chart-provider-google)",
} as const;

export const STATUS_COLORS = {
  Success: "var(--chart-success-color)",
  Fail: "var(--chart-fail)",
} as const;

export const CHART_COLORS = {
  tooltipBorder: "var(--chart-border-emphasis)",
  tooltipBackground: "var(--chart-background)",
  textPrimary: "var(--chart-text-primary)",
  textSecondary: "var(--chart-text-secondary)",
  gridLine: "var(--chart-border-emphasis)",
  backgroundTrack: "rgba(51, 65, 85, 0.5)", // slate-700 with 50% opacity
  alertPillBg: "var(--chart-alert-bg)",
  alertPillText: "var(--chart-alert-text)",
  defaultColor: "#64748b", // slate-500
} as const;

export const CHART_DIMENSIONS = {
  defaultHeight: 400,
  tooltipMinWidth: "200px",
  borderRadius: "8px",
} as const;

export const SORT_OPTIONS = {
  highLow: "high-low",
  lowHigh: "low-high",
  alphabetical: "alphabetical",
} as const;

export const DEFAULT_SORT_OPTION = SORT_OPTIONS.highLow;

export const SEVERITY_ORDER = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
} as const;

export const LAYOUT_OPTIONS = {
  horizontal: "horizontal",
  vertical: "vertical",
} as const;
