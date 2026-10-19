import { describe, expect, it } from "vitest";

import { FEATURE_FLAG } from "./shared";

describe("FEATURE_FLAG", () => {
  it("should map the skill launcher to the PostHog key the experiment uses", () => {
    expect(FEATURE_FLAG.SKILL_LAUNCHER).toBe("finding-detail-skill-launcher");
  });

  it("should not contain duplicate keys", () => {
    const keys = Object.values(FEATURE_FLAG);

    expect(new Set(keys).size).toBe(keys.length);
  });
});
