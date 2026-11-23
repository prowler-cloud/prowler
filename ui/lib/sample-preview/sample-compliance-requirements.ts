import { cache } from "react";

import { getComplianceAttributes } from "@/actions/compliances";
import type { ComplianceWatchlistResponse } from "@/actions/overview/compliance-watchlist/compliance-watchlist.types";
import {
  type AttributesData,
  REQUIREMENT_STATUS,
  type RequirementItemData,
  type RequirementStatus,
} from "@/types/compliance";

import { SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE } from "./sample-overview";
import { SAMPLE_FINDINGS } from "./sample-records";

// Requirement statuses for the sample scan: the framework catalog (no tenant
// data) evaluated against the sample findings, the way a scan would.

// Failing checks of the sample findings in the selected regions (all if none).
const failingChecks = (regions: string[]) =>
  new Set(
    SAMPLE_FINDINGS.filter(
      (finding) =>
        finding.status === "FAIL" &&
        (regions.length === 0 || regions.includes(finding.resource.region)),
    ).map((finding) => finding.check.checkId),
  );

// Checks the sample does not evaluate count as passing: a clean account.
const requirementStatus = (
  checkIds: string[],
  failing: Set<string>,
): RequirementStatus => {
  if (checkIds.length === 0) return REQUIREMENT_STATUS.MANUAL;
  return checkIds.some((checkId) => failing.has(checkId))
    ? REQUIREMENT_STATUS.FAIL
    : REQUIREMENT_STATUS.PASS;
};

export const SAMPLE_CATALOG_STATUS = {
  READY: "ready",
  // The API is still loading the catalog (HTTP 503), like the real page.
  WARMING: "warming",
  UNAVAILABLE: "unavailable",
} as const;

interface SampleComplianceDetailReady {
  status: typeof SAMPLE_CATALOG_STATUS.READY;
  attributesData: AttributesData;
  requirements: RequirementItemData[];
}

interface SampleComplianceDetailPending {
  status:
    | typeof SAMPLE_CATALOG_STATUS.WARMING
    | typeof SAMPLE_CATALOG_STATUS.UNAVAILABLE;
}

export type SampleComplianceDetail =
  | SampleComplianceDetailReady
  | SampleComplianceDetailPending;

const getSampleCatalog = cache((complianceId: string) =>
  // No scan id: the catalog of the provider that declares the framework.
  getComplianceAttributes(complianceId),
);

/** The framework's requirements with sample statuses for `region` (comma-separated). */
export const getSampleComplianceDetail = cache(
  async (
    complianceId: string,
    region?: string,
  ): Promise<SampleComplianceDetail> => {
    const attributesData = await getSampleCatalog(complianceId);
    if (attributesData && "warming" in attributesData) {
      return { status: SAMPLE_CATALOG_STATUS.WARMING };
    }
    if (
      !attributesData ||
      !("data" in attributesData) ||
      !Array.isArray(attributesData.data)
    ) {
      return { status: SAMPLE_CATALOG_STATUS.UNAVAILABLE };
    }

    const typed = attributesData as AttributesData;
    const failing = failingChecks(region ? region.split(",") : []);
    return {
      status: SAMPLE_CATALOG_STATUS.READY,
      attributesData: typed,
      requirements: typed.data.map((item) => ({
        type: "compliance-requirements-details",
        id: item.id,
        attributes: {
          framework: item.attributes.framework,
          version: item.attributes.version,
          description: item.attributes.description,
          status: requirementStatus(
            item.attributes.attributes.check_ids ?? [],
            failing,
          ),
        },
      })),
    };
  },
);

type WatchlistItem = ComplianceWatchlistResponse["data"][number];

/** Card totals from the same requirements; the fixed figures if a catalog is missing. */
export const getSampleComplianceTotals = async (): Promise<WatchlistItem[]> =>
  Promise.all(
    SAMPLE_COMPLIANCE_WATCHLIST_RESPONSE.data.map(async (item) => {
      const detail = await getSampleComplianceDetail(item.id);
      if (detail.status !== SAMPLE_CATALOG_STATUS.READY) return item;

      const count = (status: RequirementStatus) =>
        detail.requirements.filter(
          (requirement) => requirement.attributes.status === status,
        ).length;
      const passed = count(REQUIREMENT_STATUS.PASS);
      const failed = count(REQUIREMENT_STATUS.FAIL);
      const manual = count(REQUIREMENT_STATUS.MANUAL);
      return {
        ...item,
        attributes: {
          ...item.attributes,
          requirements_passed: passed,
          requirements_failed: failed,
          requirements_manual: manual,
          total_requirements: passed + failed + manual,
        },
      };
    }),
  );
