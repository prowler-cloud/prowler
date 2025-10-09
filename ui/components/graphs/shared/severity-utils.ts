import { SEVERITY_COLORS } from "./chart-constants";

export function getSeverityColorByRiskScore(riskScore: number): string {
  if (riskScore >= 7) return SEVERITY_COLORS.Critical;
  if (riskScore >= 5) return SEVERITY_COLORS.High;
  if (riskScore >= 3) return SEVERITY_COLORS.Medium;
  if (riskScore >= 1) return SEVERITY_COLORS.Low;
  return SEVERITY_COLORS.Informational;
}

export function getSeverityColorByName(name: string): string | undefined {
  return SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS];
}
