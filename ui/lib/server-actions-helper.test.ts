import * as Sentry from "@sentry/nextjs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  isErrorAlreadyReported,
  markErrorAsReported,
} from "@/sentry/event-policy";

import { handleApiError, handleApiResponse } from "./server-actions-helper";

vi.mock("@sentry/nextjs", () => ({
  captureException: vi.fn(),
  captureMessage: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
}));

vi.mock("@/lib/helper", () => ({
  GENERIC_SERVER_ERROR_MESSAGE:
    "Server is temporarily unavailable. Please try again in a few minutes.",
  getErrorMessage: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
  parseStringify: (value: unknown) => value,
  sanitizeErrorMessage: (message: string, fallback: string) =>
    /<html\b|<\/?body\b|<\/?h1\b/i.test(message) ? fallback : message.trim(),
}));

describe("server-actions-helper", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("handleApiResponse", () => {
    it("should throw a generic server error instead of raw HTML for 5xx responses", async () => {
      // Given
      const response = new Response(
        "<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center></body></html>",
        {
          status: 502,
          statusText: "Bad Gateway",
          headers: { "content-type": "text/html" },
        },
      );

      // When / Then
      await expect(handleApiResponse(response)).rejects.toThrow(
        "Server is temporarily unavailable. Please try again in a few minutes.",
      );
    });

    it("should not capture controlled 4xx API validation responses", async () => {
      // Given
      const response = new Response(
        JSON.stringify({ errors: [{ detail: "Provider already exists" }] }),
        { status: 409, statusText: "Conflict" },
      );

      // When
      const result = await handleApiResponse(response);

      // Then
      expect(Sentry.captureException).not.toHaveBeenCalled();
      expect(result).toMatchObject({
        error: "Provider already exists",
        status: 409,
      });
    });

    it.each([418, 429])(
      "should capture unexpected %s API client failures before returning them",
      async (status) => {
        // Given
        const response = new Response(
          JSON.stringify({ message: "Unexpected API contract failure" }),
          { status, statusText: "Unexpected Client Failure" },
        );

        // When
        const result = await handleApiResponse(response);

        // Then
        expect(Sentry.captureException).toHaveBeenCalledTimes(1);
        expect(Sentry.captureException).toHaveBeenCalledWith(
          expect.any(Error),
          expect.objectContaining({
            tags: expect.objectContaining({
              api_error: true,
              error_source: "handleApiResponse",
              error_type: "client_error",
              status_code: status.toString(),
            }),
          }),
        );
        expect(result).toMatchObject({
          error: "Unexpected API contract failure",
          status,
        });
      },
    );

    it("should capture and mark server errors before throwing", async () => {
      // Given
      const response = new Response(
        JSON.stringify({ message: "backend down" }),
        {
          status: 500,
          statusText: "Internal Server Error",
        },
      );

      // When
      await expect(handleApiResponse(response)).rejects.toThrow("backend down");

      // Then
      expect(Sentry.captureException).toHaveBeenCalledTimes(1);
      const capturedError = vi.mocked(Sentry.captureException).mock
        .calls[0]?.[0];
      expect(isErrorAlreadyReported(capturedError)).toBe(true);
    });

    it("should fingerprint server errors by pathname without query string", async () => {
      // Given
      const response = new Response(
        JSON.stringify({ message: "backend down" }),
        {
          status: 500,
          statusText: "Internal Server Error",
        },
      );
      Object.defineProperty(response, "url", {
        value: "https://api.prowler.test/api/v1/providers?tenant=123",
      });

      // When
      await expect(handleApiResponse(response)).rejects.toThrow("backend down");

      // Then
      expect(Sentry.captureException).toHaveBeenCalledWith(
        expect.any(Error),
        expect.objectContaining({
          fingerprint: ["api-server-error", "500", "/api/v1/providers"],
        }),
      );
    });

    it("should fingerprint unexpected client failures by pathname without query string", async () => {
      // Given
      const response = new Response(
        JSON.stringify({ message: "Unexpected API contract failure" }),
        { status: 429, statusText: "Too Many Requests" },
      );
      Object.defineProperty(response, "url", {
        value: "https://api.prowler.test/api/v1/scans?page=2",
      });

      // When
      await handleApiResponse(response);

      // Then
      expect(Sentry.captureException).toHaveBeenCalledWith(
        expect.any(Error),
        expect.objectContaining({
          fingerprint: ["api-client-contract-error", "429", "/api/v1/scans"],
        }),
      );
    });
  });

  describe("handleApiError", () => {
    it("should not recapture errors that were already reported", () => {
      // Given
      const error = new Error("Already reported failure");
      vi.spyOn(console, "error").mockImplementation(() => undefined);
      markErrorAsReported(error);

      // When
      const result = handleApiError(error);

      // Then
      expect(Sentry.captureException).not.toHaveBeenCalled();
      expect(result).toEqual({ error: "Already reported failure" });
    });

    it("should capture unmarked request failure errors", () => {
      // Given
      const error = new Error("Request failed unexpectedly");
      vi.spyOn(console, "error").mockImplementation(() => undefined);

      // When
      const result = handleApiError(error);

      // Then
      expect(Sentry.captureException).toHaveBeenCalledTimes(1);
      expect(Sentry.captureException).toHaveBeenCalledWith(
        error,
        expect.objectContaining({
          tags: expect.objectContaining({
            error_source: "handleApiError",
            error_type: "unexpected_error",
          }),
        }),
      );
      expect(isErrorAlreadyReported(error)).toBe(true);
      expect(result).toEqual({ error: "Request failed unexpectedly" });
    });

    it("should capture unmarked runtime errors that include expected HTTP status numbers", () => {
      // Given
      const error = new Error("Runtime worker 401 crashed unexpectedly");
      vi.spyOn(console, "error").mockImplementation(() => undefined);

      // When
      const result = handleApiError(error);

      // Then
      expect(Sentry.captureException).toHaveBeenCalledTimes(1);
      expect(Sentry.captureException).toHaveBeenCalledWith(
        error,
        expect.objectContaining({
          tags: expect.objectContaining({
            error_source: "handleApiError",
            error_type: "unexpected_error",
          }),
        }),
      );
      expect(result).toEqual({
        error: "Runtime worker 401 crashed unexpectedly",
      });
    });
  });
});
