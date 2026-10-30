import { describe, expect, it } from "vitest";

import {
  resolveSamplePreviewState,
  SAMPLE_PREVIEW_STAGE,
} from "./sample-preview-state";

const NEW_TENANT = {
  enabled: true,
  hasCompletedScan: false,
  hasProviders: false,
  runningScan: null,
};

describe("resolveSamplePreviewState", () => {
  it("shows the sample to a tenant that has not connected a provider", () => {
    expect(resolveSamplePreviewState(NEW_TENANT)).toEqual({
      active: true,
      stage: SAMPLE_PREVIEW_STAGE.NO_PROVIDER,
      runningScan: null,
    });
  });

  it("keeps the sample while the first scan runs, with its real progress", () => {
    const runningScan = { id: "scan-1", progress: 43 };

    expect(
      resolveSamplePreviewState({
        ...NEW_TENANT,
        hasProviders: true,
        runningScan,
      }),
    ).toEqual({
      active: true,
      stage: SAMPLE_PREVIEW_STAGE.SCAN_RUNNING,
      runningScan,
    });
  });

  it("keeps the sample for a connected provider that has not been scanned", () => {
    expect(
      resolveSamplePreviewState({ ...NEW_TENANT, hasProviders: true }),
    ).toMatchObject({ active: true, stage: SAMPLE_PREVIEW_STAGE.NO_SCAN });
  });

  it("drops the sample once the tenant has a completed scan of its own", () => {
    expect(
      resolveSamplePreviewState({
        ...NEW_TENANT,
        hasProviders: true,
        hasCompletedScan: true,
      }),
    ).toEqual({ active: false });
  });

  it("shows the real page when the scan lookup failed", () => {
    expect(
      resolveSamplePreviewState({ ...NEW_TENANT, hasCompletedScan: undefined }),
    ).toEqual({ active: false });
  });

  it("never shows the sample where the deployment has not enabled it", () => {
    expect(
      resolveSamplePreviewState({ ...NEW_TENANT, enabled: false }),
    ).toEqual({ active: false });
  });
});
