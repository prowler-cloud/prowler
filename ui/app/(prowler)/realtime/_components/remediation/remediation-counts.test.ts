import { describe, expect, it } from "vitest";

import { remediationCounts } from "./remediation-counts";

describe("remediationCounts", () => {
  it("adds the statuses that need a person", () => {
    expect(
      remediationCounts({
        fixed_verified: 23,
        pr_opened: 5,
        dry_run: 11,
        fix_failed: 1,
        still_failing: 2,
        pr_blocked: 1,
        reverted: 4,
      }),
    ).toEqual({ verified: 23, prsOpened: 5, dryRun: 11, attention: 4 });
  });

  it("is all zeroes without actions", () => {
    expect(remediationCounts({})).toEqual({
      verified: 0,
      prsOpened: 0,
      dryRun: 0,
      attention: 0,
    });
  });
});
