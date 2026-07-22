"use server";

import * as Sentry from "@sentry/nextjs";

import type { ScanBinaryResult } from "@/actions/scans/scans";
import {
  apiBaseUrl,
  GENERIC_SERVER_ERROR_MESSAGE,
  getAuthHeaders,
  getErrorMessage,
} from "@/lib";
import { hasActionError } from "@/lib/action-errors";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

import type {
  CrossAccountApiFilters,
  CrossAccountOverviewResponse,
  CrossAccountOverviewResult,
  LatestCrossProviderPdf,
} from "../_types";
import {
  CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
  CROSS_PROVIDER_OVERVIEW_RESULT_STATUS,
} from "../_types";

const CROSS_ACCOUNT_API_PATH = "/cross-account-compliance-overviews";

/** Error payload shapes the PDF endpoints emit (JSON:API or plain). */
interface PdfEndpointErrorBody {
  errors?: Array<{ detail?: string }>;
  error?: string;
  message?: string;
}

/** Cross-account sibling of the cross-provider action module's helper: a
 *  user-safe message from a failed PDF endpoint response, with 5xx reported
 *  to Sentry. `operation` must be a STATIC route template. */
const getPdfEndpointErrorMessage = async (
  response: Response,
  fallbackMessage: string,
  operation: string,
): Promise<string> => {
  const contentType = response.headers.get("content-type")?.toLowerCase() || "";
  const errorData: PdfEndpointErrorBody | null = contentType.includes(
    "text/html",
  )
    ? null
    : await response.json().catch(() => null);

  if (response.status >= 500) {
    Sentry.captureException(
      new Error(
        `Cross-account PDF request failed (${response.status}) at ${operation}`,
      ),
      {
        tags: {
          api_error: true,
          status_code: response.status.toString(),
          error_type: SentryErrorType.SERVER_ERROR,
          error_source: SentryErrorSource.SERVER_ACTION,
        },
        level: "error",
        contexts: {
          api_response: {
            status: response.status,
            statusText: response.statusText,
            operation,
          },
        },
      },
    );
    return GENERIC_SERVER_ERROR_MESSAGE;
  }

  return (
    errorData?.errors?.[0]?.detail ||
    errorData?.error ||
    errorData?.message ||
    fallbackMessage
  );
};

/** Appends the required identity params + shared filters to a request URL. */
const applyCrossAccountParams = (
  url: URL,
  complianceId: string,
  providerType: string,
  filters?: CrossAccountApiFilters,
) => {
  url.searchParams.set("filter[compliance_id]", complianceId);
  url.searchParams.set("filter[provider_type]", providerType);

  if (filters?.scanIds && filters.scanIds.length > 0) {
    url.searchParams.set("filter[scan__in]", filters.scanIds.join(","));
  }
  const paramMap = {
    "filter[provider_id__in]": filters?.providerIds,
    "filter[provider_groups__in]": filters?.providerGroups,
  };
  for (const [key, value] of Object.entries(paramMap)) {
    if (value && value.trim().length > 0) {
      url.searchParams.set(key, value);
    }
  }
};

/**
 * Aggregate a regular (per-provider) compliance framework across the latest
 * completed scan of every visible account of one provider type (Prowler
 * Cloud only — the OSS API has no such endpoint).
 *
 * When `filters.scanIds` is omitted the API auto-selects the latest COMPLETED
 * scan per account. Non-2xx responses are returned as structured action
 * errors so callers can reuse the app-wide 402/403 handlers, mirroring
 * `getCrossProviderComplianceOverview`.
 */
export const getCrossAccountComplianceOverview = async ({
  complianceId,
  providerType,
  filters,
}: {
  complianceId: string;
  providerType: string;
  filters?: CrossAccountApiFilters;
}): Promise<CrossAccountOverviewResult> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${CROSS_ACCOUNT_API_PATH}`);
  applyCrossAccountParams(url, complianceId, providerType, filters);

  try {
    const response = await fetch(url.toString(), { headers });
    const responseData = await handleApiResponse(response);

    if (hasActionError(responseData)) {
      return {
        status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR,
        result: responseData,
      };
    }

    return {
      status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS,
      response: responseData as CrossAccountOverviewResponse,
    };
  } catch (error) {
    console.error("Error fetching cross-account compliance overview:", error);
    return {
      status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR,
      message: CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
    };
  }
};

/**
 * Trigger ad-hoc generation of the combined cross-account compliance PDF.
 * Mirrors `generateCrossProviderPdf`: returns the async task id so the
 * caller can track it and download via {@link getCrossAccountPdfBinary}.
 * Pass the exact `scanIds` currently on screen so the report matches the
 * displayed data instead of racing a scan completing in between.
 */
export const generateCrossAccountPdf = async ({
  complianceId,
  providerType,
  filters,
  reportName,
}: {
  complianceId: string;
  providerType: string;
  filters?: CrossAccountApiFilters;
  /** Optional download filename; sanitized server-side. */
  reportName?: string;
}): Promise<{ taskId: string } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${CROSS_ACCOUNT_API_PATH}/pdf`);
  applyCrossAccountParams(url, complianceId, providerType, filters);
  if (reportName) url.searchParams.set("report_name", reportName);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });

    if (!response.ok) {
      throw new Error(
        await getPdfEndpointErrorMessage(
          response,
          "Unable to start PDF generation. Contact support if the issue continues.",
          `POST ${CROSS_ACCOUNT_API_PATH}/pdf`,
        ),
      );
    }

    const json = await response.json();
    const taskId = json?.data?.id;
    if (!taskId) {
      throw new Error("Unexpected response starting PDF generation.");
    }

    return { taskId };
  } catch (error) {
    return { error: getErrorMessage(error) };
  }
};

/**
 * Fetch the finished cross-account PDF for a task started by
 * {@link generateCrossAccountPdf}. Same 202-pending / 2xx-binary / error-JSON
 * protocol (and shared `ScanBinaryResult` shape) as the cross-provider
 * download action.
 */
export const getCrossAccountPdfBinary = async (
  taskId: string,
): Promise<ScanBinaryResult> => {
  const safeTaskId = taskId.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(safeTaskId)) {
    return { error: "Invalid task identifier." };
  }

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}${CROSS_ACCOUNT_API_PATH}/pdf/${encodeURIComponent(safeTaskId)}`,
  );

  try {
    const response = await fetch(url.toString(), { headers });

    if (response.status === 202) {
      const json = await response.json();
      return {
        pending: true,
        state: json?.data?.attributes?.state,
        taskId: json?.data?.id,
      };
    }

    if (!response.ok) {
      throw new Error(
        await getPdfEndpointErrorMessage(
          response,
          "Unable to retrieve the compliance PDF report. Contact support if the issue continues.",
          `GET ${CROSS_ACCOUNT_API_PATH}/pdf/{taskId}`,
        ),
      );
    }

    const contentDisposition =
      response.headers.get("content-disposition") || "";
    const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
    const filename = filenameMatch?.[1] || "cross-account-compliance.pdf";

    const arrayBuffer = await response.arrayBuffer();
    const base64 = Buffer.from(arrayBuffer).toString("base64");

    return { success: true, data: base64, filename };
  } catch (error) {
    return { error: getErrorMessage(error) };
  }
};

/**
 * Check whether a cross-account PDF already exists for the given filters —
 * same degrade-to-`null` contract as `getLatestCrossProviderPdf` (404 means
 * "not generated yet"; the report goes stale the moment any account
 * completes a new scan).
 */
export const getLatestCrossAccountPdf = async ({
  complianceId,
  providerType,
  filters,
}: {
  complianceId: string;
  providerType: string;
  filters?: CrossAccountApiFilters;
}): Promise<LatestCrossProviderPdf | null> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${CROSS_ACCOUNT_API_PATH}/pdf/latest`);
  applyCrossAccountParams(url, complianceId, providerType, filters);

  try {
    const response = await fetch(url.toString(), { headers });

    if (response.status === 404) return null;

    if (!response.ok) {
      throw new Error(
        await getPdfEndpointErrorMessage(
          response,
          "Unable to check for an existing PDF report.",
          `GET ${CROSS_ACCOUNT_API_PATH}/pdf/latest`,
        ),
      );
    }

    const json = await response.json();
    const taskId = json?.data?.id;
    if (!taskId) return null;

    return {
      taskId,
      filename: json?.data?.attributes?.result?.filename,
      completedAt: json?.data?.attributes?.completed_at,
    };
  } catch (error) {
    console.error("Error checking for an existing cross-account PDF:", error);
    return null;
  }
};
