"use server";

import * as Sentry from "@sentry/nextjs";

import type { ScanBinaryResult } from "@/actions/scans";
import {
  apiBaseUrl,
  GENERIC_SERVER_ERROR_MESSAGE,
  getAuthHeaders,
  getErrorMessage,
} from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

async function getCrossProviderPdfErrorMessage(
  response: Response,
  fallbackMessage: string,
  // A static route template / operation name (e.g.
  // ``cross-provider-compliance-overviews/generate-pdf/{taskId}/download``).
  // Passed explicitly instead of derived from ``response.url`` so no dynamic
  // path segment (``taskId``) or query param (user-typed ``report_name``) is
  // ever forwarded to Sentry.
  operation: string,
): Promise<string> {
  const contentType = response.headers.get("content-type")?.toLowerCase() || "";

  if (contentType.includes("text/html")) {
    return GENERIC_SERVER_ERROR_MESSAGE;
  }

  const errorData = await response.json().catch(() => null);

  // Report unexpected server/parse failures to Sentry — the returned message
  // stays sanitized (callers pass it through ``getErrorMessage``), but these
  // PDF generate/download/latest endpoints would otherwise go unmonitored,
  // unlike everything routed through ``handleApiResponse``.
  if (response.status >= 500 || errorData === null) {
    Sentry.captureException(
      new Error(
        `Cross-provider PDF request failed (${response.status}): ${response.statusText}`,
      ),
      {
        tags: {
          api_error: true,
          status_code: response.status.toString(),
          error_type:
            response.status >= 500
              ? SentryErrorType.SERVER_ERROR
              : SentryErrorType.REQUEST_PROCESSING,
          error_source: SentryErrorSource.SERVER_ACTION,
        },
        level: response.status >= 500 ? "error" : "warning",
        contexts: {
          api_response: {
            status: response.status,
            statusText: response.statusText,
            // Route template only — never the resolved URL, which would carry
            // the task id / user-typed report name.
            operation,
          },
        },
      },
    );
  }

  return (
    errorData?.errors?.[0]?.detail ||
    errorData?.errors?.detail ||
    errorData?.error ||
    errorData?.message ||
    (response.status >= 500 ? GENERIC_SERVER_ERROR_MESSAGE : fallbackMessage)
  );
}

export const getCompliancesOverview = async ({
  scanId,
  region,
  filters = {},
}: {
  scanId?: string;
  region?: string | string[];
  filters?: Record<string, string | string[] | undefined>;
} = {}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/compliance-overviews`);

  const setParam = (key: string, value?: string | string[]) => {
    if (!value) return;

    const serializedValue = Array.isArray(value) ? value.join(",") : value;
    if (serializedValue.trim().length > 0) {
      url.searchParams.set(key, serializedValue);
    }
  };

  Object.entries(filters).forEach(([key, value]) => setParam(key, value));

  setParam("filter[scan_id]", scanId);
  setParam("filter[region__in]", region);
  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliances overview:", error);
    return undefined;
  }
};

export const getComplianceOverviewMetadataInfo = async ({
  sort = "",
  filters = {},
}: {
  sort?: string;
  filters?: Record<string, string | string[] | undefined>;
} = {}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/compliance-overviews/metadata`);

  if (sort) url.searchParams.append("sort", sort);

  Object.entries(filters).forEach(([key, value]) => {
    // Define filters to exclude and check for valid values
    if (key !== "filter[search]" && value && String(value).trim() !== "") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance overview metadata info:", error);
    return undefined;
  }
};

export const getComplianceAttributes = async (
  complianceId: string,
  scanId?: string,
) => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const url = new URL(`${apiBaseUrl}/compliance-overviews/attributes`);
    url.searchParams.append("filter[compliance_id]", complianceId);
    // Pass the scan so multi-provider universal frameworks (e.g. CSA CCM)
    // resolve the check IDs for the scan's provider instead of defaulting to
    // the first provider that declares the framework.
    if (scanId) {
      url.searchParams.append("filter[scan_id]", scanId);
    }

    const response = await fetch(url.toString(), {
      headers,
    });

    // The compliance catalog is still warming after a deploy/restart. Signal
    // the page to render the "still loading" state instead of letting this
    // become a thrown 5xx (which would be captured as a server error).
    if (response.status === 503) {
      return { warming: true as const, status: 503 };
    }

    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance attributes:", error);
    return undefined;
  }
};

export const getComplianceRequirements = async ({
  complianceId,
  scanId,
  region,
}: {
  complianceId: string;
  scanId: string;
  region?: string | string[];
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const url = new URL(`${apiBaseUrl}/compliance-overviews/requirements`);
    url.searchParams.append("filter[compliance_id]", complianceId);
    url.searchParams.append("filter[scan_id]", scanId);

    if (region) {
      const regionValue = Array.isArray(region) ? region.join(",") : region;
      url.searchParams.append("filter[region__in]", regionValue);
      //remove page param
    }
    url.searchParams.delete("page");

    const response = await fetch(url.toString(), {
      headers,
    });

    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching compliance requirements:", error);
    return undefined;
  }
};

/**
 * Aggregate a universal compliance framework across one scan per compatible
 * provider. Backed by ``GET /cross-provider-compliance-overviews/`` (Prowler
 * Cloud only — the OSS API does not expose this endpoint).
 *
 * ``scanIds`` is optional: when omitted, the API auto-selects the most recent
 * COMPLETED scan for every provider in the tenant whose type is declared
 * compatible by the universal framework (further narrowed by ``providerTypes``
 * and by RBAC visibility).
 */
export const getCrossProviderComplianceOverview = async ({
  complianceId,
  scanIds,
  providerTypes,
  providerIds,
  providerGroups,
  regions,
}: {
  complianceId: string;
  scanIds?: string[];
  providerTypes?: string | string[];
  providerIds?: string | string[];
  providerGroups?: string | string[];
  regions?: string | string[];
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/cross-provider-compliance-overviews`);

  const setParam = (key: string, value?: string | string[]) => {
    if (!value) return;
    const serializedValue = Array.isArray(value) ? value.join(",") : value;
    if (serializedValue.trim().length > 0) {
      url.searchParams.set(key, serializedValue);
    }
  };

  setParam("filter[compliance_id]", complianceId);
  if (scanIds && scanIds.length > 0) {
    setParam("filter[scan__in]", scanIds);
  }
  setParam("filter[provider_type__in]", providerTypes);
  setParam("filter[provider_id__in]", providerIds);
  setParam("filter[provider_groups__in]", providerGroups);
  setParam("filter[region__in]", regions);

  try {
    const response = await fetch(url.toString(), { headers });

    if (response.status === 402) return { redirectTo: "/billing" };

    return await handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching cross-provider compliance overview:", error);
    return undefined;
  }
};

/**
 * Trigger ad-hoc generation of the combined cross-provider compliance PDF.
 *
 * Backed by ``POST /cross-provider-compliance-overviews/generate-pdf``. The
 * PDF itself is built asynchronously by a Celery task and is not ready when
 * this call returns — it dispatches the job and returns the ``Task`` id so
 * the caller can poll it (via ``getTask``) and then fetch the finished file
 * with {@link getCrossProviderCompliancePdf}.
 *
 * ``scanIds`` should be the exact scan ids the caller currently has on
 * screen (``attributes.scan_ids`` from the overview response) so the PDF
 * matches what the user is looking at instead of re-resolving "latest scan
 * per provider" a second time, which could race a scan that completes
 * in between.
 *
 * ``providerTypes``/``providerIds``/``providerGroups`` should be the same
 * ``filter[provider_type__in]`` / ``filter[provider_id__in]`` /
 * ``filter[provider_groups__in]`` values currently applied to the on-screen
 * cross-provider view (same shape ``getCrossProviderComplianceOverview``
 * takes) so the generated PDF only includes the providers the user has
 * filtered down to, instead of silently widening back out to every
 * compatible provider.
 */
export const generateCrossProviderCompliancePdf = async ({
  complianceId,
  scanIds,
  providerTypes,
  providerIds,
  providerGroups,
  regions,
  onlyFailed,
  includeManual,
  reportName,
}: {
  complianceId: string;
  scanIds?: string[];
  providerTypes?: string | string[];
  providerIds?: string | string[];
  providerGroups?: string | string[];
  regions?: string | string[];
  onlyFailed?: boolean;
  includeManual?: boolean;
  /** Optional user-chosen download filename. Sanitized server-side (a
   *  `.pdf` extension is enforced); omit for a unique timestamped default. */
  reportName?: string;
}): Promise<{ taskId: string } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(
    `${apiBaseUrl}/cross-provider-compliance-overviews/generate-pdf`,
  );

  const setParam = (key: string, value?: string | string[]) => {
    if (!value) return;
    const serializedValue = Array.isArray(value) ? value.join(",") : value;
    if (serializedValue.trim().length > 0) {
      url.searchParams.set(key, serializedValue);
    }
  };

  url.searchParams.set("filter[compliance_id]", complianceId);
  if (scanIds && scanIds.length > 0) {
    url.searchParams.set("filter[scan__in]", scanIds.join(","));
  }
  setParam("filter[provider_type__in]", providerTypes);
  setParam("filter[provider_id__in]", providerIds);
  setParam("filter[provider_groups__in]", providerGroups);
  setParam("filter[region__in]", regions);
  setParam("report_name", reportName);
  if (onlyFailed !== undefined) {
    url.searchParams.set("only_failed", String(onlyFailed));
  }
  if (includeManual !== undefined) {
    url.searchParams.set("include_manual", String(includeManual));
  }

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
    });

    if (!response.ok) {
      throw new Error(
        await getCrossProviderPdfErrorMessage(
          response,
          "Unable to start PDF generation. Contact support if the issue continues.",
          "cross-provider-compliance-overviews/generate-pdf",
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
 * Fetch the finished cross-provider compliance PDF for a task started by
 * {@link generateCrossProviderCompliancePdf}.
 *
 * Backed by ``GET .../generate-pdf/{taskId}/download``, which mirrors the
 * same 202-pending / 2xx-binary / error-JSON protocol as the per-scan report
 * endpoints — returns a {@link ScanBinaryResult} so callers can reuse
 * ``downloadFile`` from ``lib/helper.ts`` unchanged.
 */
export const getCrossProviderCompliancePdf = async (
  taskId: string,
): Promise<ScanBinaryResult> => {
  const headers = await getAuthHeaders({ contentType: false });
  // ``taskId`` reaches the URL path, so constrain it to the task-id charset
  // (UUIDs) before interpolating — this closes the SSRF vector of a value
  // smuggling ``/``, ``..`` or a host into the request path.
  const safeTaskId = taskId.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(safeTaskId)) {
    return { error: "Invalid task identifier." };
  }
  const url = new URL(
    `${apiBaseUrl}/cross-provider-compliance-overviews/generate-pdf/${encodeURIComponent(safeTaskId)}/download`,
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
        await getCrossProviderPdfErrorMessage(
          response,
          "Unable to retrieve the compliance PDF report. Contact support if the issue continues.",
          "cross-provider-compliance-overviews/generate-pdf/{taskId}/download",
        ),
      );
    }

    const contentDisposition =
      response.headers.get("content-disposition") || "";
    const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
    const filename = filenameMatch?.[1] || "compliance-report.pdf";

    const arrayBuffer = await response.arrayBuffer();
    const base64 = Buffer.from(arrayBuffer).toString("base64");

    return { success: true, data: base64, filename };
  } catch (error) {
    return { error: getErrorMessage(error) };
  }
};

/** A previously-generated cross-provider PDF report matching a given set
 *  of filters, ready to download immediately (no polling required). */
export interface LatestCrossProviderPdfReport {
  taskId: string;
  filename?: string;
  /** ISO timestamp the report finished generating (``completed_at``), if
   *  the backend provided one. */
  generatedAt?: string;
}

export type LatestCrossProviderPdfResult =
  | ({ available: true } & LatestCrossProviderPdfReport)
  | { available: false }
  | { error: string };

/**
 * Check whether a cross-provider compliance PDF has already been generated
 * for the given filters, so the UI can offer "Download" immediately instead
 * of always making the user click "Generate" and wait.
 *
 * Backed by ``GET .../generate-pdf/latest``: 200 with a Task body means a
 * matching, still-current report exists (the backend only matches reports
 * generated from the exact scan set these filters currently resolve to —
 * a report goes stale and this starts returning "not available" the moment
 * any contributing provider completes a new scan); 404 means "not generated
 * yet" (a normal, expected state — not surfaced as an error).
 *
 * Same param shape as {@link generateCrossProviderCompliancePdf} so callers
 * can pass through the exact same filter values to both.
 */
export const getLatestCrossProviderCompliancePdf = async ({
  complianceId,
  scanIds,
  providerTypes,
  providerIds,
  providerGroups,
  regions,
}: {
  complianceId: string;
  scanIds?: string[];
  providerTypes?: string | string[];
  providerIds?: string | string[];
  providerGroups?: string | string[];
  regions?: string | string[];
}): Promise<LatestCrossProviderPdfResult> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(
    `${apiBaseUrl}/cross-provider-compliance-overviews/generate-pdf/latest`,
  );

  const setParam = (key: string, value?: string | string[]) => {
    if (!value) return;
    const serializedValue = Array.isArray(value) ? value.join(",") : value;
    if (serializedValue.trim().length > 0) {
      url.searchParams.set(key, serializedValue);
    }
  };

  url.searchParams.set("filter[compliance_id]", complianceId);
  if (scanIds && scanIds.length > 0) {
    url.searchParams.set("filter[scan__in]", scanIds.join(","));
  }
  setParam("filter[provider_type__in]", providerTypes);
  setParam("filter[provider_id__in]", providerIds);
  setParam("filter[provider_groups__in]", providerGroups);
  setParam("filter[region__in]", regions);

  try {
    const response = await fetch(url.toString(), { headers });

    if (response.status === 404) {
      return { available: false };
    }

    if (!response.ok) {
      throw new Error(
        await getCrossProviderPdfErrorMessage(
          response,
          "Unable to check for an existing PDF report. Contact support if the issue continues.",
          "cross-provider-compliance-overviews/generate-pdf/latest",
        ),
      );
    }

    const json = await response.json();
    const taskId = json?.data?.id;
    if (!taskId) {
      return { available: false };
    }

    return {
      available: true,
      taskId,
      filename: json?.data?.attributes?.result?.filename,
      generatedAt: json?.data?.attributes?.completed_at,
    };
  } catch (error) {
    // Logged here because the caller (the compliance detail page) degrades
    // an ``{error}`` to "no report available" by design — the right UX for
    // an optional availability check, but without this log a systematically
    // failing endpoint would be indistinguishable from "never generated".
    console.error(
      "Error checking for an existing cross-provider compliance PDF:",
      error,
    );
    return { error: getErrorMessage(error) };
  }
};
