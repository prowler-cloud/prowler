import { describe, expect, it } from "vitest";

import {
  COMPLIANCE_REPORT_TYPES,
  getReportTypeForCompliance,
  getReportTypeForFramework,
  pickLatestCisPerProvider,
} from "./compliance-report-types";

describe("getReportTypeForFramework", () => {
  it("returns the framework-mapped type for single-version frameworks", () => {
    expect(getReportTypeForFramework("ENS")).toBe(COMPLIANCE_REPORT_TYPES.ENS);
    expect(getReportTypeForFramework("NIS2")).toBe(
      COMPLIANCE_REPORT_TYPES.NIS2,
    );
    expect(getReportTypeForFramework("CSA-CCM")).toBe(
      COMPLIANCE_REPORT_TYPES.CSA_CCM,
    );
    expect(getReportTypeForFramework("ProwlerThreatScore")).toBe(
      COMPLIANCE_REPORT_TYPES.THREATSCORE,
    );
  });

  it("returns undefined for CIS — callers must go through getReportTypeForCompliance", () => {
    expect(getReportTypeForFramework("CIS")).toBeUndefined();
  });

  it("returns undefined for unknown frameworks", () => {
    expect(getReportTypeForFramework("SomethingElse")).toBeUndefined();
  });

  it("returns undefined when framework is missing", () => {
    expect(getReportTypeForFramework(undefined)).toBeUndefined();
  });
});

describe("pickLatestCisPerProvider", () => {
  it("returns an empty set for an empty input", () => {
    const latest = pickLatestCisPerProvider([]);
    expect(Array.from(latest)).toEqual([]);
  });

  it("returns a single variant when only one is provided", () => {
    const latest = pickLatestCisPerProvider(["cis_5.0_aws"]);
    expect(Array.from(latest)).toEqual(["cis_5.0_aws"]);
  });

  it("selects numerically, not lexicographically (1.10 beats 1.2)", () => {
    const latest = pickLatestCisPerProvider([
      "cis_1.2_kubernetes",
      "cis_1.10_kubernetes",
    ]);
    expect(Array.from(latest)).toEqual(["cis_1.10_kubernetes"]);
  });

  it("picks the highest major version across many variants", () => {
    const latest = pickLatestCisPerProvider([
      "cis_1.4_aws",
      "cis_2.0_aws",
      "cis_5.0_aws",
      "cis_6.0_aws",
    ]);
    expect(Array.from(latest)).toEqual(["cis_6.0_aws"]);
  });

  it("breaks ties on the minor version", () => {
    const latest = pickLatestCisPerProvider([
      "cis_3.0_aws",
      "cis_3.1_aws",
      "cis_2.9_aws",
    ]);
    expect(Array.from(latest)).toEqual(["cis_3.1_aws"]);
  });

  it("considers three-part versions higher than two-part prefixes", () => {
    const latest = pickLatestCisPerProvider(["cis_3.0_aws", "cis_3.0.1_aws"]);
    expect(Array.from(latest)).toEqual(["cis_3.0.1_aws"]);
  });

  it("picks one latest per provider when multiple providers are mixed", () => {
    const latest = pickLatestCisPerProvider([
      "cis_1.4_aws",
      "cis_5.0_aws",
      "cis_2.0_azure",
      "cis_5.0_azure",
      "cis_1.12_kubernetes",
      "cis_1.8_kubernetes",
    ]);
    expect(new Set(latest)).toEqual(
      new Set(["cis_5.0_aws", "cis_5.0_azure", "cis_1.12_kubernetes"]),
    );
  });

  it("ignores non-CIS compliance ids mixed into the input", () => {
    const latest = pickLatestCisPerProvider([
      "ens_rd2022_aws",
      "nis2_aws",
      "csa_ccm_4.0_aws",
      "prowler_threatscore_aws",
      "cis_5.0_aws",
    ]);
    expect(Array.from(latest)).toEqual(["cis_5.0_aws"]);
  });

  it("skips malformed names silently", () => {
    const latest = pickLatestCisPerProvider([
      "cis_abc_aws",
      "cis_._aws",
      "cis_5._aws",
      "cis_5_aws",
      "notcis_1.0_aws",
      "cis_5.0_aws",
    ]);
    expect(Array.from(latest)).toEqual(["cis_5.0_aws"]);
  });

  it("returns an empty set when every input is malformed", () => {
    const latest = pickLatestCisPerProvider(["cis_abc_aws", "notcis_1.0_aws"]);
    expect(latest.size).toBe(0);
  });
});

describe("getReportTypeForCompliance", () => {
  it("returns the framework-mapped type for single-version frameworks", () => {
    expect(getReportTypeForCompliance("ENS", "ens_rd2022_aws", false)).toBe(
      COMPLIANCE_REPORT_TYPES.ENS,
    );
    expect(getReportTypeForCompliance("NIS2", "nis2_aws", false)).toBe(
      COMPLIANCE_REPORT_TYPES.NIS2,
    );
  });

  it("returns CIS only when isLatestCisForProvider is true", () => {
    expect(getReportTypeForCompliance("CIS", "cis_5.0_aws", true)).toBe(
      COMPLIANCE_REPORT_TYPES.CIS,
    );
  });

  it("hides CIS when isLatestCisForProvider is false (fail-closed default)", () => {
    // An older CIS variant must NOT surface a PDF button because the
    // backend only generates the PDF for the latest version.
    expect(
      getReportTypeForCompliance("CIS", "cis_1.4_aws", false),
    ).toBeUndefined();
  });

  it("defaults isLatestCisForProvider to false when omitted", () => {
    expect(getReportTypeForCompliance("CIS", "cis_5.0_aws")).toBeUndefined();
  });

  it("returns undefined for unknown frameworks", () => {
    expect(
      getReportTypeForCompliance("SomethingElse", "unknown_1.0_foo", false),
    ).toBeUndefined();
  });
});
