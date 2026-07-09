"use server";

import * as Sentry from "@sentry/nextjs";

import type { ScanBinaryResult } from "@/actions/scans/scans";
import {
  apiBaseUrl,
  GENERIC_SERVER_ERROR_MESSAGE,
  getAuthHeaders,
  getErrorMessage,
} from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

import type {
  BillingRedirect,
  CrossProviderApiFilters,
  LatestCrossProviderPdf,
} from "../_types";

const CROSS_PROVIDER_API_PATH = "/cross-provider-compliance-overviews";

/**
 * Extracts a user-safe message from a failed PDF endpoint response and, for
 * unexpected failures, reports it to Sentry. `operation` must be a STATIC
 * route template (e.g. `POST .../generate-pdf/{taskId}/download`) — never the
 * resolved URL, which would carry the task id or a user-typed report name.
 */
const getPdfEndpointErrorMessage = async (
  response: Response,
  fallbackMessage: string,
  operation: string,
): Promise<string> => {
  const contentType = response.headers.get("content-type")?.toLowerCase() || "";
  const errorData = contentType.includes("text/html")
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
    "filter[region__in]": filters.regions,
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
 * scan per compatible provider. A 402 (subscription gate) resolves to
 * `{ redirectTo: "/billing" }` so callers can forward the billing signal.
 */
export const getCrossProviderComplianceOverview = async ({
  complianceId,
  filters,
}: {
  complianceId: string;
  filters?: CrossProviderApiFilters;
}): Promise<unknown | BillingRedirect | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${CROSS_PROVIDER_API_PATH}`);
  url.searchParams.set("filter[compliance_id]", complianceId);
  applyFilters(url, filters);

  try {
    const response = await fetch(url.toString(), { headers });

    if (response.status === 402) {
      return { redirectTo: "/billing" };
    }

    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching cross-provider compliance overview:", error);
    return undefined;
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
  onlyFailed,
  includeManual,
}: {
  complianceId: string;
  filters?: CrossProviderApiFilters;
  /** Optional download filename; sanitized server-side. */
  reportName?: string;
  onlyFailed?: boolean;
  includeManual?: boolean;
}): Promise<{ taskId: string } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${CROSS_PROVIDER_API_PATH}/generate-pdf`);
  url.searchParams.set("filter[compliance_id]", complianceId);
  applyFilters(url, filters);
  if (reportName) url.searchParams.set("report_name", reportName);
  if (onlyFailed !== undefined) {
    url.searchParams.set("only_failed", String(onlyFailed));
  }
  if (includeManual !== undefined) {
    url.searchParams.set("include_manual", String(includeManual));
  }

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });

    if (!response.ok) {
      throw new Error(
        await getPdfEndpointErrorMessage(
          response,
          "Unable to start PDF generation. Contact support if the issue continues.",
          `POST ${CROSS_PROVIDER_API_PATH}/generate-pdf`,
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
    `${apiBaseUrl}${CROSS_PROVIDER_API_PATH}/generate-pdf/${encodeURIComponent(safeTaskId)}/download`,
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
          `GET ${CROSS_PROVIDER_API_PATH}/generate-pdf/{taskId}/download`,
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
  const url = new URL(
    `${apiBaseUrl}${CROSS_PROVIDER_API_PATH}/generate-pdf/latest`,
  );
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
          `GET ${CROSS_PROVIDER_API_PATH}/generate-pdf/latest`,
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
