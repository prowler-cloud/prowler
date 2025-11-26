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

export const SEVERITY_FILTER_MAP: Record<string, SeverityLevel> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  Informational: "informational",
};
