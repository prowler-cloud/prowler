import type { FindingTriageStatus } from "@/types/findings-triage";

export const TRIAGE_STATUS_TEXT_CLASS = {
  open: "text-text-error-primary",
  under_review: "text-text-warning-primary",
  remediating: "text-bg-data-info",
  resolved: "text-bg-pass",
  risk_accepted: "text-bg-pass",
  false_positive: "text-text-neutral-secondary",
  reopened: "text-text-error-primary",
} as const satisfies Record<FindingTriageStatus, string>;
