export const SEVERITY_COLORS = {
  Informational: "var(--color-info)",
  Low: "var(--color-warning)",
  Medium: "var(--color-warning-emphasis)",
  High: "var(--color-danger)",
  Critical: "var(--color-danger-emphasis)",
} as const;

export const CHART_COLORS = {
  tooltipBorder: "var(--color-slate-700)",
  tooltipBackground: "var(--color-slate-800)",
  textPrimary: "var(--color-white)",
  textSecondary: "var(--color-slate-400)",
  gridLine: "var(--color-slate-700)",
  backgroundTrack: "rgba(51, 65, 85, 0.5)", // slate-700 with 50% opacity
  alertPillBg: "var(--color-alert-pill-bg)",
  alertPillText: "var(--color-alert-pill-text)",
  defaultColor: "var(--color-slate-500)", // Default fallback color for charts
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
