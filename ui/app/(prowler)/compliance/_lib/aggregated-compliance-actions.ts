import * as Sentry from "@sentry/nextjs";

import type { ScanBinaryResult } from "@/actions/scans/scans";
import {
  GENERIC_SERVER_ERROR_MESSAGE,
  getAuthHeaders,
  getErrorMessage,
} from "@/lib";
import { hasActionError, type ActionErrorResult } from "@/lib/action-errors";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

import type { LatestCrossProviderPdf } from "../_types";
import {
  CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
  CROSS_PROVIDER_OVERVIEW_RESULT_STATUS,
} from "../_types";

const AGGREGATED_COMPLIANCE_REQUEST_TIMEOUT_MS = 30_000;

interface PdfEndpointErrorBody {
  errors?: Array<{ detail?: string }>;
  error?: string;
  message?: string;
}

type AggregatedComplianceOverviewResult<TResponse> =
  | {
      status: typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS;
      response: TResponse;
    }
  | {
      status: typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR;
      result: ActionErrorResult;
    }
  | {
      status: typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR;
      message: string;
    };

const captureRequestFailure = (
  error: unknown,
  operation: string,
  timedOut: boolean,
) => {
  const capturedError =
    error instanceof Error ? error : new Error(getErrorMessage(error));
  Sentry.captureException(capturedError, {
    tags: {
      error_source: SentryErrorSource.SERVER_ACTION,
      error_type: SentryErrorType.SERVER_ACTION_ERROR,
      request_timed_out: timedOut,
    },
    level: "error",
    contexts: {
      api_request: { operation },
    },
  });
};

/** Fetch wrapper used by every aggregated-compliance endpoint. It keeps the
 * static route template in telemetry, aborts stalled upstream requests, and
 * always clears its timer once the request settles. */
const fetchAggregatedCompliance = async (
  url: URL,
  init: RequestInit,
  operation: string,
): Promise<Response> => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(
      new Error(
        `Aggregated compliance request timed out after ${AGGREGATED_COMPLIANCE_REQUEST_TIMEOUT_MS}ms`,
      ),
    );
  }, AGGREGATED_COMPLIANCE_REQUEST_TIMEOUT_MS);

  try {
    return await fetch(url.toString(), {
      ...init,
      signal: controller.signal,
    });
  } catch (error) {
    captureRequestFailure(error, operation, controller.signal.aborted);
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
};

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
        `Aggregated compliance PDF request failed (${response.status}) at ${operation}`,
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

export const getAggregatedComplianceOverview = async <TResponse>(
  url: URL,
  operation: string,
): Promise<AggregatedComplianceOverviewResult<TResponse>> => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetchAggregatedCompliance(
      url,
      { headers },
      operation,
    );
    const responseData = await handleApiResponse(response);

    if (hasActionError(responseData)) {
      return {
        status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR,
        result: responseData,
      };
    }

    return {
      status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS,
      response: responseData as TResponse,
    };
  } catch (error) {
    console.error("Error fetching aggregated compliance overview:", error);
    return {
      status: CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR,
      message: CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
    };
  }
};

export const generateAggregatedCompliancePdf = async (
  url: URL,
  operation: string,
): Promise<{ taskId: string } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetchAggregatedCompliance(
      url,
      { method: "POST", headers },
      operation,
    );

    if (!response.ok) {
      throw new Error(
        await getPdfEndpointErrorMessage(
          response,
          "Unable to start PDF generation. Contact support if the issue continues.",
          operation,
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

export const getAggregatedCompliancePdfBinary = async ({
  url,
  operation,
  defaultFilename,
}: {
  url: URL;
  operation: string;
  defaultFilename: string;
}): Promise<ScanBinaryResult> => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetchAggregatedCompliance(
      url,
      { headers },
      operation,
    );

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
          operation,
        ),
      );
    }

    const contentDisposition =
      response.headers.get("content-disposition") || "";
    const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
    const filename = filenameMatch?.[1] || defaultFilename;
    const arrayBuffer = await response.arrayBuffer();

    return {
      success: true,
      data: Buffer.from(arrayBuffer).toString("base64"),
      filename,
    };
  } catch (error) {
    return { error: getErrorMessage(error) };
  }
};

export const getLatestAggregatedCompliancePdf = async (
  url: URL,
  operation: string,
): Promise<LatestCrossProviderPdf | null> => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetchAggregatedCompliance(
      url,
      { headers },
      operation,
    );

    if (response.status === 404) return null;

    if (!response.ok) {
      throw new Error(
        await getPdfEndpointErrorMessage(
          response,
          "Unable to check for an existing PDF report.",
          operation,
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
    console.error("Error checking for an aggregated compliance PDF:", error);
    return null;
  }
};
