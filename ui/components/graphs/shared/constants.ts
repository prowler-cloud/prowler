export const SEVERITY_COLORS = {
  Informational: "var(--bg-data-info)",
  Info: "var(--bg-data-info)",
  Low: "var(--bg-data-low)",
  Medium: "var(--bg-data-medium)",
  High: "var(--bg-data-high)",
  Critical: "var(--bg-data-critical)",
} as const;

export const PROVIDER_COLORS = {
  AWS: "var(--bg-data-aws)",
  Azure: "var(--bg-data-azure)",
  Google: "var(--bg-data-gcp)",
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
  backgroundTrack: "var(--bg-neutral-tertiary)",
  alertPillBg: "var(--chart-alert-bg)",
  alertPillText: "var(--chart-alert-text)",
  defaultColor: "var(--text-neutral-tertiary)",
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
