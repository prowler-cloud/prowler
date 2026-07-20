import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  captureExceptionMock,
  captureMessageMock,
  revalidatePathMock,
  unstableRethrowMock,
} = vi.hoisted(() => ({
  captureExceptionMock: vi.fn(),
  captureMessageMock: vi.fn(),
  revalidatePathMock: vi.fn(),
  unstableRethrowMock: vi.fn((error: unknown) => {
    if (error instanceof Error && error.message === "NEXT_REDIRECT") {
      throw error;
    }
  }),
}));

vi.mock("@sentry/nextjs", () => ({
  captureException: captureExceptionMock,
  captureMessage: captureMessageMock,
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
}));

vi.mock("next/navigation", () => ({
  unstable_rethrow: unstableRethrowMock,
}));

vi.mock("./helper", () => ({
  GENERIC_SERVER_ERROR_MESSAGE:
    "Server is temporarily unavailable. Please try again in a few minutes.",
  getErrorMessage: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
  parseStringify: (value: unknown) => value,
  sanitizeErrorMessage: (message: string, fallback: string) =>
    /<html\b|<\/?body\b|<\/?h1\b/i.test(message) ? fallback : message.trim(),
}));

import { handleApiError, handleApiResponse } from "./server-actions-helper";

describe("server action error handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("rethrows authentication redirect control flow before converting errors", () => {
    // Given
    const redirectError = new Error("NEXT_REDIRECT");

    // When / Then
    expect(() => handleApiError(redirectError)).toThrow(redirectError);
  });

  it("returns ordinary errors as action data", () => {
    // Given
    const ordinaryError = new Error("API unavailable");

    // When
    const result = handleApiError(ordinaryError);

    // Then
    expect(result).toEqual({ error: "API unavailable" });
  });

  it("throws a generic server error instead of raw HTML for 5xx responses", async () => {
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
    const result = handleApiResponse(response);
    await expect(result).rejects.toThrow(
      "Server is temporarily unavailable. Please try again in a few minutes.",
    );
  });

  it("returns authentication failures as ordinary API error data", async () => {
    // Given
    const response = new Response(
      JSON.stringify({ errors: [{ detail: "Token is invalid or expired" }] }),
      {
        status: 401,
        headers: { "content-type": "application/vnd.api+json" },
      },
    );

    // When
    const result = await handleApiResponse(response);

    // Then
    expect(result).toEqual({
      error: "Token is invalid or expired",
      errors: [{ detail: "Token is invalid or expired" }],
      status: 401,
    });
  });

  it("returns authorization failures without redirecting the session", async () => {
    // Given
    const response = new Response(
      JSON.stringify({ errors: [{ detail: "Permission denied" }] }),
      {
        status: 403,
        headers: { "content-type": "application/vnd.api+json" },
      },
    );

    // When
    const result = await handleApiResponse(response);

    // Then
    expect(result).toMatchObject({ error: "Permission denied", status: 403 });
  });
});
