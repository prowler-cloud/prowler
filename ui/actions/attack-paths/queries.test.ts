import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

import { executeQuery } from "./queries";

describe("executeQuery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("returns a friendly message when API response handling throws", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(null, {
        status: 500,
      }),
    );
    handleApiResponseMock.mockRejectedValue(
      new Error("Server error (500): backend database unavailable"),
    );

    // When
    const result = await executeQuery(
      "550e8400-e29b-41d4-a716-446655440000",
      "aws-iam-statements-allow-all-actions",
    );

    // Then
    expect(handleApiResponseMock).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      error:
        "Server is temporarily unavailable. Please try again in a few minutes.",
      status: 503,
    });
  });

  it("returns undefined and skips fetch for invalid scan ids", async () => {
    // When
    const result = await executeQuery(
      "not-a-uuid",
      "aws-iam-statements-allow-all-actions",
    );

    // Then
    expect(result).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });
});
