import { describe, expect, it } from "vitest";

import { buildComplianceDetailPath } from "./compliance-detail-url";

describe("buildComplianceDetailPath", () => {
  it("builds the detail path with the encoded title and required params", () => {
    const path = buildComplianceDetailPath({
      title: "CIS 2.0 (AWS)",
      complianceId: "cis_2.0_aws",
      version: "2.0",
      scanId: "scan-123",
    });

    expect(path).toBe(
      "/compliance/CIS%202.0%20(AWS)?complianceId=cis_2.0_aws&version=2.0&scanId=scan-123",
    );
  });

  it("propagates the region filter only when present", () => {
    const withRegion = buildComplianceDetailPath({
      title: "ens",
      complianceId: "ens_rd2022_aws",
      version: "RD2022",
      scanId: "scan-1",
      regionFilter: "eu-west-1",
    });
    const withoutRegion = buildComplianceDetailPath({
      title: "ens",
      complianceId: "ens_rd2022_aws",
      version: "RD2022",
      scanId: "scan-1",
      regionFilter: null,
    });

    expect(withRegion).toContain("filter%5Bregion__in%5D=eu-west-1");
    expect(withoutRegion).not.toContain("region__in");
  });
});
