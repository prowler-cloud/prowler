import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  captureExceptionMock,
  captureMessageMock,
  revalidatePathMock,
  redirectMock,
  fetchMaintenanceStatusMock,
} = vi.hoisted(() => ({
  captureExceptionMock: vi.fn(),
  captureMessageMock: vi.fn(),
  revalidatePathMock: vi.fn(),
  redirectMock: vi.fn(() => {
    // Mirror Next's real `redirect()`: it throws to unwind the call stack via
    // the NEXT_REDIRECT digest rather than returning normally.
    throw new Error("NEXT_REDIRECT");
  }),
  fetchMaintenanceStatusMock: vi.fn(),
}));

vi.mock("@sentry/nextjs", () => ({
  captureException: captureExceptionMock,
  captureMessage: captureMessageMock,
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
}));

vi.mock("next/navigation", () => ({
  redirect: redirectMock,
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "http://api:8000/api/v1",
}));

vi.mock("@/lib/maintenance", () => ({
  MAINTENANCE_PATH: "/maintenance",
  fetchMaintenanceStatus: fetchMaintenanceStatusMock,
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

  describe('on Cloud (NEXT_PUBLIC_IS_CLOUD_ENV="true")', () => {
    beforeEach(() => {
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    });

    it("redirects to /maintenance on a 503 when maintenance mode is actually on", async () => {
      // Given
      fetchMaintenanceStatusMock.mockResolvedValueOnce({
        enabled: true,
        message: "Down for maintenance.",
        started_at: "2026-06-17T10:00:00Z",
      });
      const response = new Response(null, { status: 503 });

      // When / Then
      const result = handleApiResponse(response);
      await expect(result).rejects.toThrow("NEXT_REDIRECT");
      expect(redirectMock).toHaveBeenCalledWith("/maintenance");
    });

    it("does NOT redirect on a 503 when maintenance mode is off (transient error, or the status probe itself fails open) — falls through to normal 5xx handling instead", async () => {
      // Given: `fetchMaintenanceStatus` fails open (2s timeout → `enabled:
      // false`) on any error, so a status-check blip resolves identically to a
      // confirmed "MM off" here — this asserts the helper's behavior on that
      // resolved value regardless of why it came back `false`. Falling through
      // means the normal 5xx path takes over and throws the generic server
      // error rather than redirecting to /maintenance.
      fetchMaintenanceStatusMock.mockResolvedValueOnce({
        enabled: false,
        message: null,
        started_at: null,
      });
      const response = new Response("Service Unavailable", {
        status: 503,
        statusText: "Service Unavailable",
      });

      // When / Then
      const result = handleApiResponse(response);
      await expect(result).rejects.toThrow(
        "Server is temporarily unavailable. Please try again in a few minutes.",
      );
      expect(redirectMock).not.toHaveBeenCalled();
    });
  });

  describe('self-hosted (NEXT_PUBLIC_IS_CLOUD_ENV is not "true")', () => {
    it("is a no-op on a 503: never probes maintenance status and never redirects, falling straight through to normal 5xx handling", async () => {
      // Given: Maintenance Mode is a Cloud-only feature (see
      // lib/maintenance.ts) — self-hosted deployments have no MM status
      // endpoint, so a 503 there is always a normal server error.
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
      const response = new Response("Service Unavailable", {
        status: 503,
        statusText: "Service Unavailable",
      });

      // When / Then
      const result = handleApiResponse(response);
      await expect(result).rejects.toThrow(
        "Server is temporarily unavailable. Please try again in a few minutes.",
      );
      expect(fetchMaintenanceStatusMock).not.toHaveBeenCalled();
      expect(redirectMock).not.toHaveBeenCalled();
    });

    it("is also a no-op when NEXT_PUBLIC_IS_CLOUD_ENV is unset", async () => {
      // Given
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", undefined);
      const response = new Response(null, { status: 503 });

      // When / Then
      const result = handleApiResponse(response);
      await expect(result).rejects.toThrow();
      expect(fetchMaintenanceStatusMock).not.toHaveBeenCalled();
      expect(redirectMock).not.toHaveBeenCalled();
    });
  });
});
