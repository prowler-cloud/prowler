import * as Sentry from "@sentry/nextjs";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { apiBaseUrl } from "@/lib";
import { fetchMaintenanceStatus, MAINTENANCE_PATH } from "@/lib/maintenance";
import { isCloud } from "@/lib/shared/env";
import { SentryErrorSource, SentryErrorType } from "@/sentry";

import {
  GENERIC_SERVER_ERROR_MESSAGE,
  getErrorMessage,
  parseStringify,
  sanitizeErrorMessage,
} from "./helper";

/**
 * Helper function to handle API responses consistently
 * Includes Sentry error tracking for debugging
 */
export const handleApiResponse = async (
  response: Response,
  pathToRevalidate?: string,
  parse = true,
) => {
  if (!response.ok) {
    // Maintenance Mode is Cloud-only (see lib/maintenance.ts): self-hosted
    // has no MM status endpoint, so a 503 there is always a normal server
    // error, never a maintenance redirect — skip the check entirely.
    //
    // On Cloud: when MM flips on between the proxy check and a server action
    // firing, the API returns 503 for every endpoint. Redirect to the
    // full-screen /maintenance landing page instead of surfacing a generic
    // server error. `redirect()` throws NEXT_REDIRECT, which Next turns into
    // a client navigation, so this short-circuits before the
    // Sentry-capturing 5xx branch below.
    //
    // A 503 alone isn't proof of MM though — any transient upstream error
    // (DB blip, deploy rollout) also returns 503 and must NOT be conflated
    // with real maintenance. Confirm against the status endpoint first;
    // `fetchMaintenanceStatus` fails open (2s timeout → `enabled: false`), so
    // a status-check blip falls through to normal error handling instead of
    // redirecting.
    if (isCloud() && response.status === 503) {
      const status = await fetchMaintenanceStatus(apiBaseUrl);
      if (status.enabled) {
        redirect(MAINTENANCE_PATH);
      }
    }

    // Read error body safely; prefer JSON, fallback to plain text
    const rawErrorText = await response.text().catch(() => "");
    const contentType = response.headers.get("content-type")?.toLowerCase();
    let errorData: any = null;
    try {
      errorData = rawErrorText ? JSON.parse(rawErrorText) : null;
    } catch {
      errorData = null;
    }

    const errorsArray = Array.isArray(errorData?.errors)
      ? (errorData.errors as any[])
      : undefined;
    const parsedErrorMessage =
      errorsArray?.[0]?.detail || errorData?.error || errorData?.message;
    const fallbackErrorMessage =
      response.status >= 500 || contentType?.includes("text/html")
        ? GENERIC_SERVER_ERROR_MESSAGE
        : response.statusText || "Oops! Something went wrong.";
    const rawErrorMessage =
      parsedErrorMessage ||
      (response.status < 500 && rawErrorText.trim()) ||
      fallbackErrorMessage;
    const errorDetail = sanitizeErrorMessage(
      String(rawErrorMessage),
      fallbackErrorMessage,
    );

    // Capture error context for Sentry
    const errorContext = {
      status: response.status,
      statusText: response.statusText,
      url: response.url,
      errorDetail,
      pathToRevalidate,
    };

    // 5XX errors - Server errors (high priority)
    if (response.status >= 500) {
      const serverError = new Error(
        errorDetail ||
          `Server error (${response.status}): The server encountered an error. Please try again later.`,
      );

      Sentry.captureException(serverError, {
        tags: {
          api_error: true,
          status_code: response.status.toString(),
          error_type: SentryErrorType.SERVER_ERROR,
          error_source: SentryErrorSource.HANDLE_API_RESPONSE,
        },
        level: "error",
        contexts: {
          api_response: errorContext,
        },
        fingerprint: [
          "api-server-error",
          response.status.toString(),
          response.url,
        ],
      });

      throw serverError;
    }

    // Client errors (4xx) - Only capture unexpected ones
    if (![401, 403, 404].includes(response.status)) {
      const clientError = new Error(
        errorDetail ||
          `Request failed (${response.status}): ${response.statusText}`,
      );

      Sentry.captureException(clientError, {
        tags: {
          api_error: true,
          status_code: response.status.toString(),
          error_type: SentryErrorType.CLIENT_ERROR,
          error_source: SentryErrorSource.HANDLE_API_RESPONSE,
        },
        level: "warning",
        contexts: {
          api_response: errorContext,
        },
        fingerprint: [
          "api-client-error",
          response.status.toString(),
          response.url,
        ],
      });
    }

    return errorsArray
      ? { error: errorDetail, errors: errorsArray, status: response.status }
      : ({ error: errorDetail, status: response.status } as any);
  }

  // Handle empty or no-content responses gracefully (e.g., 204, empty body)
  if (response.status === 204) {
    if (pathToRevalidate && pathToRevalidate !== "") {
      revalidatePath(pathToRevalidate);
    }
    return { success: true, status: response.status } as any;
  }

  // Read raw text to determine if there's a body to parse
  const rawText = await response.text();
  const hasBody = rawText && rawText.trim().length > 0;

  if (!hasBody) {
    if (pathToRevalidate && pathToRevalidate !== "") {
      revalidatePath(pathToRevalidate);
    }
    return { success: true, status: response.status } as any;
  }

  let data: any;
  try {
    data = JSON.parse(rawText);
  } catch (_e) {
    // If body isn't valid JSON, return as text payload
    data = { data: rawText };
  }

  if (pathToRevalidate && pathToRevalidate !== "") {
    revalidatePath(pathToRevalidate);
  }

  return parse ? parseStringify(data) : data;
};

/**
 * Helper function to handle API errors consistently
 * Includes Sentry error tracking
 */
export const handleApiError = (error: unknown): { error: string } => {
  console.error(error);

  // Check if this error was already captured by handleApiResponse
  const isAlreadyCaptured =
    error instanceof Error &&
    (error.message.includes("Server error") ||
      error.message.includes("Request failed"));

  // Only capture if not already captured by handleApiResponse
  if (!isAlreadyCaptured) {
    if (error instanceof Error) {
      // Don't capture expected errors
      if (
        !error.message.includes("401") &&
        !error.message.includes("403") &&
        !error.message.includes("404")
      ) {
        Sentry.captureException(error, {
          tags: {
            error_source: SentryErrorSource.HANDLE_API_ERROR,
            error_type: SentryErrorType.UNEXPECTED_ERROR,
          },
          level: "error",
          contexts: {
            error_details: {
              message: error.message,
              stack: error.stack,
            },
          },
        });
      }
    } else {
      // Capture non-Error objects
      Sentry.captureMessage(
        `Non-Error object in handleApiError: ${String(error)}`,
        {
          level: "warning",
          tags: {
            error_source: SentryErrorSource.HANDLE_API_ERROR,
            error_type: SentryErrorType.NON_ERROR_OBJECT,
          },
          extra: {
            error: error,
          },
        },
      );
    }
  }

  return {
    error: getErrorMessage(error),
  };
};
