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

const FAILING_CHECKS = new Set(
  SAMPLE_FINDINGS.filter((finding) => finding.status === "FAIL").map(
    (finding) => finding.check.checkId,
  ),
);

// Checks the sample does not evaluate count as passing: a clean account.
const requirementStatus = (checkIds: string[]): RequirementStatus => {
  if (checkIds.length === 0) return REQUIREMENT_STATUS.MANUAL;
  return checkIds.some((checkId) => FAILING_CHECKS.has(checkId))
    ? REQUIREMENT_STATUS.FAIL
    : REQUIREMENT_STATUS.PASS;
};

export interface SampleComplianceDetail {
  attributesData: AttributesData;
  requirements: RequirementItemData[];
}

/** The framework's requirements with sample statuses; null if the catalog is unavailable. */
export const getSampleComplianceDetail = cache(
  async (complianceId: string): Promise<SampleComplianceDetail | null> => {
    // No scan id: the catalog of the provider that declares the framework.
    const attributesData = await getComplianceAttributes(complianceId);
    if (!attributesData || !("data" in attributesData)) return null;
    if (!Array.isArray(attributesData.data)) return null;

    const typed = attributesData as AttributesData;
    return {
      attributesData: typed,
      requirements: typed.data.map((item) => ({
        type: "compliance-requirements-details",
        id: item.id,
        attributes: {
          framework: item.attributes.framework,
          version: item.attributes.version,
          description: item.attributes.description,
          status: requirementStatus(item.attributes.attributes.check_ids ?? []),
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
      if (!detail) return item;

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
