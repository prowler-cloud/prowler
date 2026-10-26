import { describe, expect, it } from "vitest";

import { FEATURE_FLAG, FEATURE_FLAG_STATE } from "./shared";

describe("FEATURE_FLAG", () => {
  it("should map each flag to the key PostHog knows it by", () => {
    expect(FEATURE_FLAG).toEqual({
      ISSUES: "issues-feature",
      BILLING_SYSTEM_METRONOME: "BILLING_SYSTEM_METRONOME",
      FINDINGS_TRIAL_PREVIEW: "findings-trial-preview",
    });
  });

  it("should not contain duplicate keys", () => {
    const keys = Object.values(FEATURE_FLAG);

    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("FEATURE_FLAG_STATE", () => {
  it("should distinguish the unresolved state from a resolved off", () => {
    expect(FEATURE_FLAG_STATE).toEqual({
      PENDING: "pending",
      ON: "on",
      OFF: "off",
    });
  });
});
