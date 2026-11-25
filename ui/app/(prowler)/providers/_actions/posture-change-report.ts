"use server";

import type { ScanBinaryResult } from "@/actions/scans/scans";
import {
  generateAggregatedCompliancePdf,
  getAggregatedCompliancePdfBinary,
} from "@/app/(prowler)/compliance/_lib/aggregated-compliance-actions";
import { apiBaseUrl } from "@/lib";

const POSTURE_CHANGE_API_PATH = "/posture-change-reports";

export const generatePostureChangeReport = async ({
  providerId,
  dateFrom,
  dateTo,
  reportName,
}: {
  providerId: string;
  dateFrom: string;
  dateTo: string;
  reportName?: string;
}): Promise<{ taskId: string } | { error: string }> => {
  const url = new URL(`${apiBaseUrl}${POSTURE_CHANGE_API_PATH}`);
  url.searchParams.set("provider_id", providerId);
  url.searchParams.set("date_from", dateFrom);
  url.searchParams.set("date_to", dateTo);
  if (reportName) url.searchParams.set("report_name", reportName);
  return generateAggregatedCompliancePdf(
    url,
    `POST ${POSTURE_CHANGE_API_PATH}`,
  );
};

export const getPostureChangeReportBinary = async (
  taskId: string,
): Promise<ScanBinaryResult> => {
  const safeTaskId = taskId.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(safeTaskId)) {
    return { error: "Invalid task identifier." };
  }
  const url = new URL(
    `${apiBaseUrl}${POSTURE_CHANGE_API_PATH}/${encodeURIComponent(safeTaskId)}`,
  );
  return getAggregatedCompliancePdfBinary({
    url,
    operation: `GET ${POSTURE_CHANGE_API_PATH}/{taskId}`,
    defaultFilename: "posture-change-report.pdf",
  });
};
