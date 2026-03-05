import * as Sentry from "@sentry/nextjs";
import { revalidatePath } from "next/cache";

import { SentryErrorSource, SentryErrorType } from "@/sentry";

import { getErrorMessage, parseStringify } from "./helper";

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
    // Read error body safely; prefer JSON, fallback to plain text
    const rawErrorText = await response.text().catch(() => "");
    let errorData: any = null;
    try {
      errorData = rawErrorText ? JSON.parse(rawErrorText) : null;
    } catch {
      errorData = null;
    }

    const errorsArray = Array.isArray(errorData?.errors)
      ? (errorData.errors as any[])
      : undefined;
    const errorDetail =
      errorsArray?.[0]?.detail ||
      errorData?.error ||
      errorData?.message ||
      (rawErrorText && rawErrorText.trim()) ||
      response.statusText ||
      "Oops! Something went wrong.";

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
