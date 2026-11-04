import type { SamplePreviewStage } from "./sample-preview-state";

// Window events the sample preview dispatches. Like the provider funnel, they
// carry no listener of their own: a deployment that measures the experiment
// subscribes from outside. Details are low-cardinality only.
export const SAMPLE_PREVIEW_EVENT = "prowler:sample-preview";

export const SAMPLE_PREVIEW_STEP = {
  VIEWED: "viewed",
  CTA_CLICKED: "cta_clicked",
  // The first scan completed while the sample was on screen.
  EXITED: "exited",
} as const;

export const SAMPLE_PREVIEW_PAGE = {
  OVERVIEW: "overview",
  FINDINGS: "findings",
  COMPLIANCE: "compliance",
  ISSUES: "issues",
  ATTACK_PATHS: "attack_paths",
} as const;

export type SamplePreviewPage =
  (typeof SAMPLE_PREVIEW_PAGE)[keyof typeof SAMPLE_PREVIEW_PAGE];

export const SAMPLE_PREVIEW_CTA = {
  ADD_PROVIDER: "add_provider",
  LAUNCH_SCAN: "launch_scan",
  VIEW_SCAN: "view_scan",
} as const;

export type SamplePreviewCta =
  (typeof SAMPLE_PREVIEW_CTA)[keyof typeof SAMPLE_PREVIEW_CTA];

interface SamplePreviewBaseDetail {
  page: SamplePreviewPage;
  stage: SamplePreviewStage;
}

export interface SamplePreviewViewedDetail extends SamplePreviewBaseDetail {
  step: typeof SAMPLE_PREVIEW_STEP.VIEWED;
}

export interface SamplePreviewCtaClickedDetail extends SamplePreviewBaseDetail {
  step: typeof SAMPLE_PREVIEW_STEP.CTA_CLICKED;
  cta: SamplePreviewCta;
}

export interface SamplePreviewExitedDetail extends SamplePreviewBaseDetail {
  step: typeof SAMPLE_PREVIEW_STEP.EXITED;
}

export type SamplePreviewDetail =
  | SamplePreviewViewedDetail
  | SamplePreviewCtaClickedDetail
  | SamplePreviewExitedDetail;

export function dispatchSamplePreview(detail: SamplePreviewDetail): void {
  if (typeof window === "undefined") return;
  try {
    window.dispatchEvent(
      new CustomEvent<SamplePreviewDetail>(SAMPLE_PREVIEW_EVENT, { detail }),
    );
  } catch {
    // A listener that throws must never break the page it observes.
  }
}
