import { beforeEach, describe, expect, it, vi } from "vitest";

const { captureExceptionMock, captureMessageMock, revalidatePathMock } =
  vi.hoisted(() => ({
    captureExceptionMock: vi.fn(),
    captureMessageMock: vi.fn(),
    revalidatePathMock: vi.fn(),
  }));

vi.mock("@sentry/nextjs", () => ({
  captureException: captureExceptionMock,
  captureMessage: captureMessageMock,
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
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

import { handleApiResponse } from "./server-actions-helper";

describe("server action error handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
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
});
