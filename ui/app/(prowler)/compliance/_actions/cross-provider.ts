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
  CrossProviderApiFilters,
  CrossProviderOverviewResponse,
  CrossProviderOverviewResult,
  LatestCrossProviderPdf,
} from "../_types";

const CROSS_PROVIDER_API_PATH = "/cross-provider-compliance-overviews";

const applyCrossProviderParams = (
  url: URL,
  complianceId: string,
  filters?: CrossProviderApiFilters,
) => {
  url.searchParams.set("filter[compliance_id]", complianceId);

  if (filters?.scanIds?.length) {
    url.searchParams.set("filter[scan__in]", filters.scanIds.join(","));
  }

  const params = {
    "filter[provider_type__in]": filters?.providerTypes,
    "filter[provider_id__in]": filters?.providerIds,
    "filter[provider_groups__in]": filters?.providerGroups,
  };
  for (const [key, value] of Object.entries(params)) {
    if (value?.trim()) url.searchParams.set(key, value);
  }
};

const buildCrossProviderUrl = (
  suffix: string,
  complianceId: string,
  filters?: CrossProviderApiFilters,
) => {
  const url = new URL(`${apiBaseUrl}${CROSS_PROVIDER_API_PATH}${suffix}`);
  applyCrossProviderParams(url, complianceId, filters);
  return url;
};

export const getCrossProviderComplianceOverview = async ({
  complianceId,
  filters,
}: {
  complianceId: string;
  filters?: CrossProviderApiFilters;
}): Promise<CrossProviderOverviewResult> => {
  const url = buildCrossProviderUrl("", complianceId, filters);
  return getAggregatedComplianceOverview<CrossProviderOverviewResponse>(
    url,
    `GET ${CROSS_PROVIDER_API_PATH}`,
  );
};

export const generateCrossProviderPdf = async ({
  complianceId,
  filters,
  reportName,
}: {
  complianceId: string;
  filters?: CrossProviderApiFilters;
  reportName?: string;
}): Promise<{ taskId: string } | { error: string }> => {
  const url = buildCrossProviderUrl("/pdf", complianceId, filters);
  if (reportName) url.searchParams.set("report_name", reportName);
  return generateAggregatedCompliancePdf(
    url,
    `POST ${CROSS_PROVIDER_API_PATH}/pdf`,
  );
};

export const getCrossProviderPdfBinary = async (
  taskId: string,
): Promise<ScanBinaryResult> => {
  const safeTaskId = taskId.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(safeTaskId)) {
    return { error: "Invalid task identifier." };
  }

  const url = new URL(
    `${apiBaseUrl}${CROSS_PROVIDER_API_PATH}/pdf/${encodeURIComponent(safeTaskId)}`,
  );
  return getAggregatedCompliancePdfBinary({
    url,
    operation: `GET ${CROSS_PROVIDER_API_PATH}/pdf/{taskId}`,
    defaultFilename: "cross-provider-compliance.pdf",
  });
};

export const getLatestCrossProviderPdf = async ({
  complianceId,
  filters,
}: {
  complianceId: string;
  filters?: CrossProviderApiFilters;
}): Promise<LatestCrossProviderPdf | null> => {
  const url = buildCrossProviderUrl("/pdf/latest", complianceId, filters);
  return getLatestAggregatedCompliancePdf(
    url,
    `GET ${CROSS_PROVIDER_API_PATH}/pdf/latest`,
  );
};
