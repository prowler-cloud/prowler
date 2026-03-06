/**
 * Score utility functions for ThreatScore visualization.
 * Used by threatscore-breakdown-card and threatscore-badge components.
 */

export const SCORE_THRESHOLDS = {
  SUCCESS: 80,
  WARNING: 40,
} as const;

export const SCORE_COLORS = {
  DANGER: "var(--bg-fail-primary)",
  WARNING: "var(--bg-warning-primary)",
  SUCCESS: "var(--bg-pass-primary)",
  NEUTRAL: "var(--bg-neutral-tertiary)",
} as const;

export const SCORE_LEVELS = {
  SUCCESS: "SUCCESS",
  WARNING: "WARNING",
  DANGER: "DANGER",
} as const;
export type ScoreLevel = (typeof SCORE_LEVELS)[keyof typeof SCORE_LEVELS];

export const SCORE_COLOR_VARIANTS = {
  SUCCESS: "success",
  WARNING: "warning",
  DANGER: "danger",
} as const;
export type ScoreColorVariant =
  (typeof SCORE_COLOR_VARIANTS)[keyof typeof SCORE_COLOR_VARIANTS];

export function getScoreLevel(score: number): ScoreLevel {
  if (score >= SCORE_THRESHOLDS.SUCCESS) return "SUCCESS";
  if (score >= SCORE_THRESHOLDS.WARNING) return "WARNING";
  return "DANGER";
}

export function getScoreColor(score: number): ScoreColorVariant {
  if (score >= SCORE_THRESHOLDS.SUCCESS) return "success";
  if (score >= SCORE_THRESHOLDS.WARNING) return "warning";
  return "danger";
}

export function getScoreTextClass(score: number): string {
  if (score >= SCORE_THRESHOLDS.SUCCESS) return "text-success";
  if (score >= SCORE_THRESHOLDS.WARNING) return "text-warning";
  return "text-danger";
}

export function getScoreLabel(score: number): string {
  if (score >= SCORE_THRESHOLDS.SUCCESS) return "Secure";
  if (score >= SCORE_THRESHOLDS.WARNING) return "Moderate Risk";
  return "Critical Risk";
}
