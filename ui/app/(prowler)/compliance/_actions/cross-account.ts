"use server";

import type { ScanBinaryResult } from "@/actions/scans/scans";
import { apiBaseUrl } from "@/lib";

import {
  generateAggregatedCompliancePdf,
  getAggregatedComplianceOverview,
  getAggregatedCompliancePdfBinary,
  getLatestAggregatedCompliancePdf,
} from "../_lib/aggregated-compliance-actions";
import type {
  CrossAccountApiFilters,
  CrossAccountOverviewResponse,
  CrossAccountOverviewResult,
  LatestCrossProviderPdf,
} from "../_types";

const CROSS_ACCOUNT_API_PATH = "/cross-account-compliance-overviews";

const applyCrossAccountParams = (
  url: URL,
  complianceId: string,
  providerType: string,
  filters?: CrossAccountApiFilters,
) => {
  url.searchParams.set("filter[compliance_id]", complianceId);
  url.searchParams.set("filter[provider_type]", providerType);

  if (filters?.scanIds?.length) {
    url.searchParams.set("filter[scan__in]", filters.scanIds.join(","));
  }

  const params = {
    "filter[provider_id__in]": filters?.providerIds,
    "filter[provider_groups__in]": filters?.providerGroups,
  };
  for (const [key, value] of Object.entries(params)) {
    if (value?.trim()) url.searchParams.set(key, value);
  }
};

const buildCrossAccountUrl = (
  suffix: string,
  complianceId: string,
  providerType: string,
  filters?: CrossAccountApiFilters,
) => {
  const url = new URL(`${apiBaseUrl}${CROSS_ACCOUNT_API_PATH}${suffix}`);
  applyCrossAccountParams(url, complianceId, providerType, filters);
  return url;
};

export const getCrossAccountComplianceOverview = async ({
  complianceId,
  providerType,
  filters,
}: {
  complianceId: string;
  providerType: string;
  filters?: CrossAccountApiFilters;
}): Promise<CrossAccountOverviewResult> => {
  const url = buildCrossAccountUrl("", complianceId, providerType, filters);
  return getAggregatedComplianceOverview<CrossAccountOverviewResponse>(
    url,
    `GET ${CROSS_ACCOUNT_API_PATH}`,
  );
};

export const generateCrossAccountPdf = async ({
  complianceId,
  providerType,
  filters,
  reportName,
}: {
  complianceId: string;
  providerType: string;
  filters?: CrossAccountApiFilters;
  reportName?: string;
}): Promise<{ taskId: string } | { error: string }> => {
  const url = buildCrossAccountUrl("/pdf", complianceId, providerType, filters);
  if (reportName) url.searchParams.set("report_name", reportName);
  return generateAggregatedCompliancePdf(
    url,
    `POST ${CROSS_ACCOUNT_API_PATH}/pdf`,
  );
};

export const getCrossAccountPdfBinary = async (
  taskId: string,
): Promise<ScanBinaryResult> => {
  const safeTaskId = taskId.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(safeTaskId)) {
    return { error: "Invalid task identifier." };
  }

  const url = new URL(
    `${apiBaseUrl}${CROSS_ACCOUNT_API_PATH}/pdf/${encodeURIComponent(safeTaskId)}`,
  );
  return getAggregatedCompliancePdfBinary({
    url,
    operation: `GET ${CROSS_ACCOUNT_API_PATH}/pdf/{taskId}`,
    defaultFilename: "cross-account-compliance.pdf",
  });
};

export const getLatestCrossAccountPdf = async ({
  complianceId,
  providerType,
  filters,
}: {
  complianceId: string;
  providerType: string;
  filters?: CrossAccountApiFilters;
}): Promise<LatestCrossProviderPdf | null> => {
  const url = buildCrossAccountUrl(
    "/pdf/latest",
    complianceId,
    providerType,
    filters,
  );
  return getLatestAggregatedCompliancePdf(
    url,
    `GET ${CROSS_ACCOUNT_API_PATH}/pdf/latest`,
  );
};
