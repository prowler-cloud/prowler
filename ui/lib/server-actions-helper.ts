import * as Sentry from "@sentry/nextjs";
import { revalidatePath } from "next/cache";

import { SentryErrorSource, SentryErrorType } from "@/sentry";
import {
  isErrorAlreadyReported,
  isErrorCapturedBySentry,
} from "@/sentry/event-policy";

import {
  GENERIC_SERVER_ERROR_MESSAGE,
  getErrorMessage,
  parseStringify,
  sanitizeErrorMessage,
} from "./helper";

const EXPECTED_HTTP_CLIENT_STATUS_CODES = new Set([401, 403, 404]);
const CONTROLLED_CLIENT_STATUS_CODES = new Set([400, 409, 422]);
const KNOWN_NON_ACTIONABLE_CLIENT_ERROR_MESSAGES = [
  "already exists",
  "duplicate",
] as const;
const UNKNOWN_URL_PATH_FINGERPRINT = "unknown-url-path";

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
          getSentryFingerprintUrlPath(response.url),
        ],
      });

      throw serverError;
    }

    if (
      !shouldSuppressApiClientFailure(response.status, errorDetail, errorsArray)
    ) {
      captureUnexpectedApiClientFailure(response, errorDetail, errorContext);
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
    isErrorAlreadyReported(error) || isErrorCapturedBySentry(error);

  // Only capture if not already captured by handleApiResponse.
  // HTTP status-based suppression belongs in the structured Sentry event policy,
  // not in string-only Error message matching.
  if (!isAlreadyCaptured) {
    if (error instanceof Error) {
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

function shouldSuppressApiClientFailure(
  status: number,
  errorDetail: unknown,
  errorsArray: unknown[] | undefined,
) {
  if (status < 400 || status >= 500) {
    return true;
  }

  if (EXPECTED_HTTP_CLIENT_STATUS_CODES.has(status)) {
    return true;
  }

  return (
    CONTROLLED_CLIENT_STATUS_CODES.has(status) &&
    (hasStructuredApiErrors(errorsArray) ||
      hasKnownNonActionableClientErrorMessage(errorDetail))
  );
}

function captureUnexpectedApiClientFailure(
  response: Response,
  errorDetail: unknown,
  errorContext: Record<string, unknown>,
) {
  const clientError = new Error(
    typeof errorDetail === "string"
      ? errorDetail
      : `Unexpected API client failure (${response.status})`,
  );

  Sentry.captureException(clientError, {
    tags: {
      api_error: true,
      status_code: response.status.toString(),
      error_type: SentryErrorType.CLIENT_ERROR,
      error_source: SentryErrorSource.HANDLE_API_RESPONSE,
    },
    level: "error",
    contexts: {
      api_response: errorContext,
    },
    fingerprint: [
      "api-client-contract-error",
      response.status.toString(),
      getSentryFingerprintUrlPath(response.url),
    ],
  });
}

function getSentryFingerprintUrlPath(url: string) {
  if (url.trim() === "") {
    return UNKNOWN_URL_PATH_FINGERPRINT;
  }

  try {
    const pathname = new URL(url).pathname;

    return (
      pathname
        .replace(
          /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi,
          "/:id",
        )
        .replace(/\/\d+(?=\/|$)/g, "/:id") || UNKNOWN_URL_PATH_FINGERPRINT
    );
  } catch {
    return UNKNOWN_URL_PATH_FINGERPRINT;
  }
}

function hasStructuredApiErrors(errorsArray: unknown[] | undefined) {
  return Array.isArray(errorsArray) && errorsArray.length > 0;
}

function hasKnownNonActionableClientErrorMessage(errorDetail: unknown) {
  if (typeof errorDetail !== "string") {
    return false;
  }

  const normalizedErrorDetail = errorDetail.toLowerCase();

  return KNOWN_NON_ACTIONABLE_CLIENT_ERROR_MESSAGES.some((message) =>
    normalizedErrorDetail.includes(message),
  );
}
