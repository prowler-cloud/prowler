import { describe, expect, it } from "vitest";

import { buildPerScanComplianceHref } from "./compliance-tab-url";

describe("buildPerScanComplianceHref", () => {
  it("pins the Single Scan tab when no extra params are given", () => {
    expect(buildPerScanComplianceHref()).toBe("/compliance?tab=per-scan");
  });

  it("keeps the tab first and appends the extra params", () => {
    expect(buildPerScanComplianceHref({ scanId: "scan-1" })).toBe(
      "/compliance?tab=per-scan&scanId=scan-1",
    );
  });

  it("encodes param values", () => {
    expect(buildPerScanComplianceHref({ scanId: "scan 1&tab=bogus" })).toBe(
      "/compliance?tab=per-scan&scanId=scan+1%26tab%3Dbogus",
    );
  });

  it("ignores a caller-supplied tab so the pin cannot be defeated", () => {
    expect(
      buildPerScanComplianceHref({ tab: "cross-provider", scanId: "scan-1" }),
    ).toBe("/compliance?tab=per-scan&scanId=scan-1");
  });
});
