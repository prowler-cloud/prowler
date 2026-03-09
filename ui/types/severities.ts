export const SEVERITY_LEVELS = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;

export type SeverityLevel = (typeof SEVERITY_LEVELS)[number];

export const SEVERITY_DISPLAY_NAMES: Record<SeverityLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

// CSS variables for chart libraries (Recharts) that require inline style color values
export const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  critical: "var(--color-bg-data-critical)",
  high: "var(--color-bg-data-high)",
  medium: "var(--color-bg-data-medium)",
  low: "var(--color-bg-data-low)",
  informational: "var(--color-bg-data-info)",
};

// Muted color for charts - uses CSS var() for Recharts inline style compatibility (same pattern as SEVERITY_COLORS)
export const MUTED_COLOR = "var(--color-bg-data-muted)";

export const SEVERITY_FILTER_MAP: Record<string, SeverityLevel> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  Info: "informational",
  Informational: "informational",
};

export interface SeverityLineConfig {
  dataKey: SeverityLevel;
  color: string;
  label: string;
}

// Pre-built line configs for charts (ordered from lowest to highest severity)
export const SEVERITY_LINE_CONFIGS: SeverityLineConfig[] = [
  {
    dataKey: "informational",
    color: SEVERITY_COLORS.informational,
    label: SEVERITY_DISPLAY_NAMES.informational,
  },
  {
    dataKey: "low",
    color: SEVERITY_COLORS.low,
    label: SEVERITY_DISPLAY_NAMES.low,
  },
  {
    dataKey: "medium",
    color: SEVERITY_COLORS.medium,
    label: SEVERITY_DISPLAY_NAMES.medium,
  },
  {
    dataKey: "high",
    color: SEVERITY_COLORS.high,
    label: SEVERITY_DISPLAY_NAMES.high,
  },
  {
    dataKey: "critical",
    color: SEVERITY_COLORS.critical,
    label: SEVERITY_DISPLAY_NAMES.critical,
  },
];
