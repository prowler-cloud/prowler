import { beforeEach, describe, expect, it, vi } from "vitest";

const { getComplianceAttributesMock } = vi.hoisted(() => ({
  getComplianceAttributesMock: vi.fn(),
}));

vi.mock("@/actions/compliances", () => ({
  getComplianceAttributes: getComplianceAttributesMock,
}));

import { REQUIREMENT_STATUS } from "@/types/compliance";

import {
  getSampleComplianceDetail,
  getSampleComplianceTotals,
  SAMPLE_CATALOG_STATUS,
} from "./sample-compliance-requirements";
import { SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE } from "./sample-overview";
import {
  isSampleScanFilter,
  SAMPLE_FINDINGS,
  sampleFindingsQuery,
} from "./sample-records";

const FAILING = SAMPLE_FINDINGS.find((finding) => finding.status === "FAIL")!;
const requirement = (id: string, checkIds: string[]) => ({
  type: "compliance-requirements-attributes",
  id,
  attributes: {
    framework_description: "",
    framework: "CIS",
    version: "5.0",
    description: `Requirement ${id}`,
    attributes: { metadata: [], check_ids: checkIds },
  },
});

describe("sample compliance requirements", () => {
  beforeEach(() => {
    getComplianceAttributesMock.mockReset();
  });

  it("derives each requirement's status from the sample findings", async () => {
    // Given
    getComplianceAttributesMock.mockResolvedValue({
      data: [
        requirement("1.1", [FAILING.check.checkId]),
        requirement("1.2", ["check_outside_the_sample"]),
        requirement("1.3", []),
      ],
    });

    // When
    const detail = await getSampleComplianceDetail("cis_5.0_aws");

    // Then: the catalog is read without a scan, so no tenant data is involved.
    expect(getComplianceAttributesMock).toHaveBeenCalledWith("cis_5.0_aws");
    expect(detail.status).toBe(SAMPLE_CATALOG_STATUS.READY);
    if (detail.status !== SAMPLE_CATALOG_STATUS.READY) return;
    expect(
      detail.requirements.map((item) => [item.id, item.attributes.status]),
    ).toEqual([
      ["1.1", REQUIREMENT_STATUS.FAIL],
      ["1.2", REQUIREMENT_STATUS.PASS],
      ["1.3", REQUIREMENT_STATUS.MANUAL],
    ]);
  });

  it("counts the cards from the same requirements the detail shows", async () => {
    // Given
    getComplianceAttributesMock.mockResolvedValue({
      data: [
        requirement("1.1", [FAILING.check.checkId]),
        requirement("1.2", []),
      ],
    });

    // When
    const totals = await getSampleComplianceTotals();

    // Then
    expect(totals).toHaveLength(
      SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE.data.length,
    );
    expect(totals[0].attributes).toMatchObject({
      requirements_passed: 0,
      requirements_failed: 1,
      requirements_manual: 1,
      total_requirements: 2,
    });
  });

  it("keeps the fixed totals when the catalog is unavailable", async () => {
    // Given
    getComplianceAttributesMock.mockResolvedValue(undefined);

    // When
    const totals = await getSampleComplianceTotals();

    // Then
    expect(totals).toEqual(SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE.data);
  });

  it("answers a requirement's findings for the sample scan", () => {
    // Given
    const filters = {
      "filter[scan__in]": "sample-scan",
      "filter[check_id__in]": FAILING.check.checkId,
      "filter[status__in]": "FAIL",
    };

    // When / Then
    expect(isSampleScanFilter(filters)).toBe(true);
    const findings = sampleFindingsQuery(filters);
    expect(findings.length).toBeGreaterThan(0);
    expect(
      findings.every(
        (finding) =>
          finding.check.checkId === FAILING.check.checkId &&
          finding.status === "FAIL",
      ),
    ).toBe(true);
  });

  it("evaluates statuses only on the selected regions' findings", async () => {
    // Given: a region where the failing check has no failing resource.
    const failingRegions = new Set(
      SAMPLE_FINDINGS.filter(
        (finding) =>
          finding.check.checkId === FAILING.check.checkId &&
          finding.status === "FAIL",
      ).map((finding) => finding.resource.region),
    );
    const cleanRegion = [
      "us-east-1",
      "us-west-2",
      "eu-west-1",
      "eu-central-1",
    ].find((region) => !failingRegions.has(region));
    getComplianceAttributesMock.mockResolvedValue({
      data: [requirement("1.1", [FAILING.check.checkId])],
    });

    // When
    const inFailingRegion = await getSampleComplianceDetail(
      "cis_5.0_aws",
      FAILING.resource.region,
    );
    const inCleanRegion = cleanRegion
      ? await getSampleComplianceDetail("cis_5.0_aws", cleanRegion)
      : null;

    // Then
    const status = (detail: typeof inFailingRegion | null) =>
      detail?.status === SAMPLE_CATALOG_STATUS.READY
        ? detail.requirements[0].attributes.status
        : undefined;
    expect(status(inFailingRegion)).toBe(REQUIREMENT_STATUS.FAIL);
    if (cleanRegion)
      expect(status(inCleanRegion)).toBe(REQUIREMENT_STATUS.PASS);
  });

  it("tells a warming catalog apart from other failures", async () => {
    getComplianceAttributesMock.mockResolvedValueOnce({
      warming: true,
      status: 503,
    });
    expect((await getSampleComplianceDetail("cis_5.0_aws")).status).toBe(
      SAMPLE_CATALOG_STATUS.WARMING,
    );

    getComplianceAttributesMock.mockResolvedValueOnce({
      error: "Not found",
      status: 404,
    });
    expect((await getSampleComplianceDetail("unknown")).status).toBe(
      SAMPLE_CATALOG_STATUS.UNAVAILABLE,
    );
  });
});
