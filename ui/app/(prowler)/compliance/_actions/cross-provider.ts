"use server";

import * as Sentry from "@sentry/nextjs";

import type { ScanBinaryResult } from "@/actions/scans/scans";
import {
  apiBaseUrl,
  GENERIC_SERVER_ERROR_MESSAGE,
  getErrorMessage,
} from "@/lib";
import { hasActionError } from "@/lib/action-errors";
import { getAuthHeaders } from "@/lib/auth-headers";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

import type {
  CrossProviderApiFilters,
  CrossProviderOverviewResponse,
  CrossProviderOverviewResult,
  LatestCrossProviderPdf,
} from "../_types";
import {
  CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
  CROSS_PROVIDER_OVERVIEW_RESULT_STATUS,
} from "../_types";

const CROSS_PROVIDER_API_PATH = "/cross-provider-compliance-overviews";

/** Error payload shapes the PDF endpoints emit (JSON:API or plain). */
interface PdfEndpointErrorBody {
  errors?: Array<{ detail?: string }>;
  error?: string;
  message?: string;
}

/**
 * Extracts a user-safe message from a failed PDF endpoint response and, for
 * unexpected failures, reports it to Sentry. `operation` must be a STATIC
 * route template (e.g. `GET .../pdf/{taskId}`) — never the
 * resolved URL, which would carry the task id or a user-typed report name.
 */
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

  // These endpoints bypass handleApiResponse (binary/task protocol), so
  // server failures would otherwise go unmonitored.
  if (response.status >= 500) {
    Sentry.captureException(
      new Error(
        `Cross-provider PDF request failed (${response.status}) at ${operation}`,
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

/** Appends the shared cross-provider filter params to a request URL. */
const applyFilters = (url: URL, filters?: CrossProviderApiFilters) => {
  if (!filters) return;

  if (filters.scanIds && filters.scanIds.length > 0) {
    url.searchParams.set("filter[scan__in]", filters.scanIds.join(","));
  }

  const paramMap = {
    "filter[provider_type__in]": filters.providerTypes,
    "filter[provider_id__in]": filters.providerIds,
    "filter[provider_groups__in]": filters.providerGroups,
  };
  for (const [key, value] of Object.entries(paramMap)) {
    if (value && value.trim().length > 0) {
      url.searchParams.set(key, value);
    }
  }
};

/**
 * Aggregate a universal compliance framework across one scan per compatible
 * provider (Prowler Cloud only — the OSS API has no such endpoint).
 *
 * When `filters.scanIds` is omitted the API auto-selects the latest COMPLETED
 * scan per compatible provider. Non-2xx responses are returned as structured
 * action errors so callers can reuse the app-wide 402/403 handlers.
 */
export const getCrossProviderComplianceOverview = async ({
  complianceId,
  filters,
}: {
  complianceId: string;
  filters?: CrossProviderApiFilters;
}): Promise<CrossProviderOverviewResult> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${CROSS_PROVIDER_API_PATH}`);
  url.searchParams.set("filter[compliance_id]", complianceId);
  applyFilters(url, filters);

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
      response: responseData as CrossProviderOverviewResponse,
    };
  } catch (error) {
    console.error("Error fetching cross-provider compliance overview:", error);
    return {
      status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR,
      message: CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
    };
  }
};

/**
 * Trigger ad-hoc generation of the combined cross-provider compliance PDF.
 *
 * The PDF is built asynchronously by a backend task: this returns the task id
 * so the caller can poll it and then download via
 * {@link getCrossProviderPdfBinary}. Pass the exact `scanIds` currently on
 * screen (`attributes.scan_ids`) so the report matches the displayed data
 * instead of re-resolving "latest scan per provider", which could race a scan
 * completing in between.
 */
export const generateCrossProviderPdf = async ({
  complianceId,
  filters,
  reportName,
}: {
  complianceId: string;
  filters?: CrossProviderApiFilters;
  /** Optional download filename; sanitized server-side. */
  reportName?: string;
}): Promise<{ taskId: string } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${CROSS_PROVIDER_API_PATH}/pdf`);
  url.searchParams.set("filter[compliance_id]", complianceId);
  applyFilters(url, filters);
  if (reportName) url.searchParams.set("report_name", reportName);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });

    if (!response.ok) {
      throw new Error(
        await getPdfEndpointErrorMessage(
          response,
          "Unable to start PDF generation. Contact support if the issue continues.",
          `POST ${CROSS_PROVIDER_API_PATH}/pdf`,
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
 * Fetch the finished cross-provider PDF for a task started by
 * {@link generateCrossProviderPdf}. Speaks the same 202-pending /
 * 2xx-binary / error-JSON protocol as the per-scan report endpoints, so it
 * returns the shared {@link ScanBinaryResult} shape and callers can reuse the
 * existing download plumbing unchanged.
 */
export const getCrossProviderPdfBinary = async (
  taskId: string,
): Promise<ScanBinaryResult> => {
  // The task id reaches the URL path: constrain it to the task-id charset
  // (UUIDs) so a crafted value cannot smuggle `/`, `..` or a host.
  const safeTaskId = taskId.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(safeTaskId)) {
    return { error: "Invalid task identifier." };
  }

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}${CROSS_PROVIDER_API_PATH}/pdf/${encodeURIComponent(safeTaskId)}`,
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
          `GET ${CROSS_PROVIDER_API_PATH}/pdf/{taskId}`,
        ),
      );
    }

    const contentDisposition =
      response.headers.get("content-disposition") || "";
    const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
    const filename = filenameMatch?.[1] || "cross-provider-compliance.pdf";

    const arrayBuffer = await response.arrayBuffer();
    const base64 = Buffer.from(arrayBuffer).toString("base64");

    return { success: true, data: base64, filename };
  } catch (error) {
    return { error: getErrorMessage(error) };
  }
};

/**
 * Check whether a cross-provider PDF already exists for the given filters so
 * the UI can offer "Download" immediately instead of forcing a re-generate.
 *
 * 404 means "not generated yet" — a normal state, returned as `null` rather
 * than an error. The backend only matches reports built from the exact scan
 * set the filters resolve to, so a report goes stale (→ `null`) as soon as a
 * contributing provider completes a new scan. Failures also degrade to
 * `null`: this is an optional availability check and the caller's fallback
 * (show "Generate") is always safe.
 */
export const getLatestCrossProviderPdf = async ({
  complianceId,
  filters,
}: {
  complianceId: string;
  filters?: CrossProviderApiFilters;
}): Promise<LatestCrossProviderPdf | null> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${CROSS_PROVIDER_API_PATH}/pdf/latest`);
  url.searchParams.set("filter[compliance_id]", complianceId);
  applyFilters(url, filters);

  try {
    const response = await fetch(url.toString(), { headers });

    if (response.status === 404) return null;

    if (!response.ok) {
      throw new Error(
        await getPdfEndpointErrorMessage(
          response,
          "Unable to check for an existing PDF report.",
          `GET ${CROSS_PROVIDER_API_PATH}/pdf/latest`,
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
    // Degraded on purpose, but logged: without this a systematically failing
    // endpoint would be indistinguishable from "never generated".
    console.error("Error checking for an existing cross-provider PDF:", error);
    return null;
  }
};
