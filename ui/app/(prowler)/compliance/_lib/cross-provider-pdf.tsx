"use client";

import { getCrossProviderPdfBinary } from "../_actions/cross-provider";
import type { CrossProviderApiFilters } from "../_types";

import {
  buildAggregatedCompliancePdfTaskScope,
  createAggregatedCompliancePdfHandler,
  downloadAggregatedCompliancePdf,
} from "./aggregated-compliance-pdf";

export const CROSS_PROVIDER_PDF_TASK_KIND = "cross-provider-pdf";

export const buildCrossProviderPdfTaskScope = (
  complianceId: string,
  filters: CrossProviderApiFilters,
): string =>
  buildAggregatedCompliancePdfTaskScope({
    complianceId,
    scanIds: filters.scanIds,
    providerTypes: filters.providerTypes,
    providerIds: filters.providerIds,
    providerGroups: filters.providerGroups,
  });

export const downloadCrossProviderPdf = (taskId: string): Promise<void> =>
  downloadAggregatedCompliancePdf({
    taskId,
    getPdfBinary: getCrossProviderPdfBinary,
    axisLabel: "cross-provider",
  });

export const crossProviderPdfHandler = createAggregatedCompliancePdfHandler({
  axisLabel: "cross-provider",
  downloadPdf: downloadCrossProviderPdf,
});
