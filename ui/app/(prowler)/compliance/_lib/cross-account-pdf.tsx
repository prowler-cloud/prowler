"use client";

import { getCrossAccountPdfBinary } from "../_actions/cross-account";
import type { CrossAccountApiFilters } from "../_types";

import {
  buildAggregatedCompliancePdfTaskScope,
  createAggregatedCompliancePdfHandler,
  downloadAggregatedCompliancePdf,
} from "./aggregated-compliance-pdf";

export const CROSS_ACCOUNT_PDF_TASK_KIND = "cross-account-pdf";

export const buildCrossAccountPdfTaskScope = (
  complianceId: string,
  providerType: string,
  filters: CrossAccountApiFilters,
): string =>
  buildAggregatedCompliancePdfTaskScope({
    complianceId,
    providerType,
    scanIds: filters.scanIds,
    providerIds: filters.providerIds,
    providerGroups: filters.providerGroups,
  });

export const downloadCrossAccountPdf = (taskId: string): Promise<void> =>
  downloadAggregatedCompliancePdf({
    taskId,
    getPdfBinary: getCrossAccountPdfBinary,
    axisLabel: "cross-account",
  });

export const crossAccountPdfHandler = createAggregatedCompliancePdfHandler({
  axisLabel: "cross-account",
  downloadPdf: downloadCrossAccountPdf,
});
