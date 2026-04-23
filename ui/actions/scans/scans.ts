"use server";

import { redirect } from "next/navigation";

import { apiBaseUrl, getAuthHeaders, getErrorMessage } from "@/lib";
import {
  COMPLIANCE_REPORT_DISPLAY_NAMES,
  type ComplianceReportType,
} from "@/lib/compliance/compliance-report-types";
import { runWithConcurrencyLimit } from "@/lib/concurrency";
import {
  appendSanitizedProviderTypeFilters,
  sanitizeProviderTypesCsv,
} from "@/lib/provider-filters";
import { addScanOperation } from "@/lib/sentry-breadcrumbs";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const ORGANIZATION_SCAN_CONCURRENCY_LIMIT = 5;
export const getScans = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
  fields = {},
  include = "",
}) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/scans");

  const url = new URL(`${apiBaseUrl}/scans`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);
  if (include) url.searchParams.append("include", include);

  // Handle fields parameters
  Object.entries(fields).forEach(([key, value]) => {
    url.searchParams.append(`fields[${key}]`, String(value));
  });

  appendSanitizedProviderTypeFilters(url, filters);

  try {
    const response = await fetch(url.toString(), { headers });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching scans:", error);
    return undefined;
  }
};

export const getScansByState = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/scans`);
  // Request only the necessary fields to optimize the response
  url.searchParams.append("fields[scans]", "state");
  url.searchParams.append(
    "filter[provider_type__in]",
    sanitizeProviderTypesCsv(),
  );

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching scans by state:", error);
    return undefined;
  }
};

export const getScan = async (
  scanId: string,
  { include }: { include?: string } = {},
) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/scans/${scanId}`);

  if (include) {
    url.searchParams.set("include", include);
  }

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const scanOnDemand = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const providerId = formData.get("providerId");
  const scanName = formData.get("scanName") || undefined;

  if (!providerId) {
    return { error: "Provider ID is required" };
  }

  addScanOperation("create", undefined, {
    provider_id: String(providerId),
    scan_name: scanName ? String(scanName) : undefined,
  });

  const url = new URL(`${apiBaseUrl}/scans`);

  try {
    const requestBody = {
      data: {
        type: "scans",
        attributes: scanName ? { name: scanName } : {},
        relationships: {
          provider: {
            data: {
              type: "providers",
              id: providerId,
            },
          },
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers: headers,
      body: JSON.stringify(requestBody),
    });

    const result = await handleApiResponse(response, "/scans");
    if (result?.data?.id) {
      addScanOperation("start", result.data.id);
    }
    return result;
  } catch (error) {
    addScanOperation("create");
    return handleApiError(error);
  }
};

export const scheduleDaily = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const providerId = formData.get("providerId");

  const url = new URL(`${apiBaseUrl}/schedules/daily`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "daily-schedules",
          attributes: {
            provider_id: providerId,
          },
        },
      }),
    });

    return handleApiResponse(response, "/scans");
  } catch (error) {
    return handleApiError(error);
  }
};

export const launchOrganizationScans = async (
  providerIds: string[],
  scheduleOption: "daily" | "single",
) => {
  const validProviderIds = providerIds.filter(Boolean);
  if (validProviderIds.length === 0) {
    return {
      successCount: 0,
      failureCount: 0,
      totalCount: 0,
    };
  }

  const launchResults = await runWithConcurrencyLimit(
    validProviderIds,
    ORGANIZATION_SCAN_CONCURRENCY_LIMIT,
    async (providerId) => {
      try {
        const formData = new FormData();
        formData.set("providerId", providerId);

        const result =
          scheduleOption === "daily"
            ? await scheduleDaily(formData)
            : await scanOnDemand(formData);

        return {
          providerId,
          ok: !result?.error,
          error: result?.error ? String(result.error) : null,
        };
      } catch (error) {
        return {
          providerId,
          ok: false,
          error:
            error instanceof Error ? error.message : "Failed to launch scan.",
        };
      }
    },
  );

  const summary = launchResults.reduce(
    (acc, item) => {
      if (item.ok) {
        acc.successCount += 1;
        return acc;
      }

      acc.failureCount += 1;
      acc.errors.push({
        providerId: item.providerId,
        error: item.error || "Failed to launch scan.",
      });
      return acc;
    },
    {
      successCount: 0,
      failureCount: 0,
      totalCount: validProviderIds.length,
      errors: [] as Array<{ providerId: string; error: string }>,
    },
  );

  return summary;
};

export const updateScan = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const scanId = formData.get("scanId");
  const scanName = formData.get("scanName");

  const url = new URL(`${apiBaseUrl}/scans/${scanId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "scans",
          id: scanId,
          attributes: {
            name: scanName,
          },
        },
      }),
    });

    return handleApiResponse(response, "/scans");
  } catch (error) {
    return handleApiError(error);
  }
};

export const getExportsZip = async (scanId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/scans/${scanId}/report`);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    if (response.status === 202) {
      const json = await response.json();
      const taskId = json?.data?.id;
      const state = json?.data?.attributes?.state;
      return {
        pending: true,
        state,
        taskId,
      };
    }

    if (!response.ok) {
      const errorData = await response.json();

      throw new Error(
        errorData?.errors?.detail ||
          "Unable to fetch scan report. Contact support if the issue continues.",
      );
    }

    // Get the blob data as an array buffer
    const arrayBuffer = await response.arrayBuffer();
    // Convert to base64
    const base64 = Buffer.from(arrayBuffer).toString("base64");

    return {
      success: true,
      data: base64,
      filename: `scan-${scanId}-report.zip`,
    };
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

/**
 * Discriminated union returned by {@link _fetchScanBinary}.
 *
 * Exported so `ui/lib/helper.ts::downloadFile` can type-narrow on the
 * `success` / `pending` / `error` tags without resorting to `any`.
 */
export type ScanBinaryResult =
  | { success: true; data: string; filename: string }
  | { pending: true; state: string | undefined; taskId: string | undefined }
  | { error: string };

/**
 * Shared binary-report fetcher used by CSV and PDF report downloads.
 *
 * All report endpoints (`/scans/{id}/compliance/{name}`,
 * `/scans/{id}/{reportType}`) speak the same protocol: Bearer auth, 202
 * ACCEPTED while the generation task is still running, 2xx with a binary
 * body when the artifact is ready, JSON error body otherwise. This helper
 * encapsulates all of that so the public wrappers only have to build the
 * URL and pick a filename.
 *
 * @param urlPath    Path segment under `{apiBaseUrl}/scans/{scanId}/`.
 * @param filename   Download filename to surface to the user.
 * @param errorLabel Friendly label used when the backend error body is empty.
 * @returns A ``{ success, data, filename }`` object on 2xx, a
 *          ``{ pending, state, taskId }`` object on 202, or
 *          ``{ error }`` on any failure.
 */
const _fetchScanBinary = async (
  scanId: string,
  urlPath: string,
  filename: string,
  errorLabel: string,
): Promise<ScanBinaryResult> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/scans/${scanId}/${urlPath}`);

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
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData?.errors?.detail ||
          `Unable to retrieve ${errorLabel}. Contact support if the issue continues.`,
      );
    }

    const arrayBuffer = await response.arrayBuffer();
    const base64 = Buffer.from(arrayBuffer).toString("base64");

    return { success: true, data: base64, filename };
  } catch (error) {
    return { error: getErrorMessage(error) };
  }
};

export const getComplianceCsv = async (scanId: string, complianceId: string) =>
  _fetchScanBinary(
    scanId,
    `compliance/${complianceId}`,
    `scan-${scanId}-compliance-${complianceId}.csv`,
    "compliance report",
  );

/**
 * Get a compliance PDF report for any supported framework.
 *
 * For frameworks with multiple variants per provider (currently CIS) the
 * backend generates a single PDF for the highest available version, so
 * callers only need to pass the generic report type.
 *
 * @param scanId - The scan ID
 * @param reportType - Type of report (from COMPLIANCE_REPORT_TYPES)
 * @returns Promise with the PDF data or error
 */
export const getCompliancePdfReport = async (
  scanId: string,
  reportType: ComplianceReportType,
) => {
  const reportName = COMPLIANCE_REPORT_DISPLAY_NAMES[reportType];
  return _fetchScanBinary(
    scanId,
    reportType,
    `scan-${scanId}-${reportType}.pdf`,
    `${reportName} PDF report`,
  );
};
