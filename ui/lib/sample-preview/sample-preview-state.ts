/** Why a tenant still sees sample data: what it has not done yet. */
export const SAMPLE_PREVIEW_STAGE = {
  NO_PROVIDER: "no_provider",
  NO_SCAN: "no_scan",
  SCAN_RUNNING: "scan_running",
} as const;

export type SamplePreviewStage =
  (typeof SAMPLE_PREVIEW_STAGE)[keyof typeof SAMPLE_PREVIEW_STAGE];

export interface RunningScan {
  id: string;
  progress: number;
}

export interface SamplePreviewActive {
  active: true;
  stage: SamplePreviewStage;
  runningScan: RunningScan | null;
}

export interface SamplePreviewInactive {
  active: false;
}

export type SamplePreviewState = SamplePreviewActive | SamplePreviewInactive;

export interface SamplePreviewInputs {
  enabled: boolean;
  // `undefined` = the lookup failed: the real page wins, never the sample.
  hasCompletedScan: boolean | undefined;
  hasProviders: boolean | undefined;
  runningScan: RunningScan | null | undefined;
}

const INACTIVE: SamplePreviewInactive = { active: false };

/** Sample data stands in until the tenant's first scan completes. */
export function resolveSamplePreviewState({
  enabled,
  hasCompletedScan,
  hasProviders,
  runningScan,
}: SamplePreviewInputs): SamplePreviewState {
  if (!enabled || hasCompletedScan !== false || runningScan === undefined) {
    return INACTIVE;
  }

  if (runningScan) {
    return {
      active: true,
      stage: SAMPLE_PREVIEW_STAGE.SCAN_RUNNING,
      runningScan,
    };
  }

  return {
    active: true,
    stage:
      hasProviders === false
        ? SAMPLE_PREVIEW_STAGE.NO_PROVIDER
        : SAMPLE_PREVIEW_STAGE.NO_SCAN,
    runningScan: null,
  };
}
