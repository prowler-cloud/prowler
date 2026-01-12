// CSS variable names for chart colors defined in globals.css
export const CHART_COLOR_MAP: Record<string, string> = {
  // Status colors
  Success: "--color-bg-pass",
  Pass: "--color-bg-pass",
  Fail: "--color-bg-fail",
  // Provider colors
  AWS: "--color-bg-data-aws",
  Azure: "--color-bg-data-azure",
  "Google Cloud": "--color-bg-data-gcp",
  Kubernetes: "--color-bg-data-kubernetes",
  "Microsoft 365": "--color-bg-data-m365",
  GitHub: "--color-bg-data-github",
  "Infrastructure as Code": "--color-bg-data-muted",
  "Oracle Cloud Infrastructure": "--color-bg-data-muted",
  // Severity colors
  Critical: "--color-bg-data-critical",
  High: "--color-bg-data-high",
  Medium: "--color-bg-data-medium",
  Low: "--color-bg-data-low",
  Info: "--color-bg-data-info",
  Informational: "--color-bg-data-info",
};

/**
 * Compute color value from CSS variable name at runtime.
 * SVG fill attributes cannot directly resolve CSS variables,
 * so we extract computed values from globals.css CSS variables.
 * Falls back to black (#000000) if variable not found or access fails.
 */
export function getChartColor(colorName: string): string {
  const varName = CHART_COLOR_MAP[colorName];
  if (!varName) return "#000000";

  try {
    if (typeof document === "undefined") {
      return "#000000";
    }
    return (
      getComputedStyle(document.documentElement)
        .getPropertyValue(varName)
        .trim() || "#000000"
    );
  } catch {
    return "#000000";
  }
}

export function initializeChartColors(): Record<string, string> {
  const colors: Record<string, string> = {};
  for (const [colorName] of Object.entries(CHART_COLOR_MAP)) {
    colors[colorName] = getChartColor(colorName);
  }
  return colors;
}
