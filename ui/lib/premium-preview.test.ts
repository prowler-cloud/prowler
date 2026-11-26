import { describe, expect, it } from "vitest";

import {
  getPremiumPreviewHook,
  PREMIUM_PREVIEW_FEATURE,
} from "./premium-preview";

describe("getPremiumPreviewHook", () => {
  it("builds the Exploitability Issues hook from the user's own FAIL counts", () => {
    // Given / When
    const hook = getPremiumPreviewHook(
      PREMIUM_PREVIEW_FEATURE.EXPLOITABILITY_ISSUES,
      { critical: 1284, high: 877 },
    );

    // Then
    expect(hook).toBe(
      "Your latest scans have 1,284 critical and 877 high FAIL findings. Exploitability Issues groups them into attack patterns ranked by how exploitable they are.",
    );
  });

  it.each([null, { critical: 0, high: 0 }])(
    "falls back to a generic hook without scan results (%o)",
    (failCounts) => {
      // Given / When
      const hook = getPremiumPreviewHook(
        PREMIUM_PREVIEW_FEATURE.EXPLOITABILITY_ISSUES,
        failCounts,
      );

      // Then
      expect(hook).toMatch(/^Once your Local Server has scan results/);
    },
  );
});
