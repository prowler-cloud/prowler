import { describe, expect, it } from "vitest";

import { getProwlerHubComplianceUrl } from "./prowler-hub";

describe("getProwlerHubComplianceUrl", () => {
  it("builds the Prowler Hub compliance page URL from the framework's compliance_id", () => {
    expect(getProwlerHubComplianceUrl("cis_controls_8.1")).toBe(
      "https://hub.prowler.com/compliance/cis_controls_8.1",
    );
  });

  it("works for every universal framework in the catalogue", () => {
    expect(getProwlerHubComplianceUrl("csa_ccm_4.0")).toBe(
      "https://hub.prowler.com/compliance/csa_ccm_4.0",
    );
    expect(getProwlerHubComplianceUrl("dora_2022_2554")).toBe(
      "https://hub.prowler.com/compliance/dora_2022_2554",
    );
  });
});
