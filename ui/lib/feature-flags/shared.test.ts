import { describe, expect, it } from "vitest";

import { FEATURE_FLAG } from "./shared";

describe("FEATURE_FLAG", () => {
  it("should map each flag to the key PostHog knows it by", () => {
    expect(FEATURE_FLAG).toEqual({
      SKILL_LAUNCHER: "finding-detail-skill-launcher",
      ISSUES: "issues-feature",
      BILLING_SYSTEM_METRONOME: "BILLING_SYSTEM_METRONOME",
    });
  });

  it("should not contain duplicate keys", () => {
    const keys = Object.values(FEATURE_FLAG);

    expect(new Set(keys).size).toBe(keys.length);
  });
});
