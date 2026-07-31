import { beforeEach, describe, expect, it, vi } from "vitest";

const { authMock, getAuthHeadersIfAvailableMock, getRequiredAuthHeadersMock } =
  vi.hoisted(() => ({
    authMock: vi.fn(),
    getAuthHeadersIfAvailableMock: vi.fn(),
    getRequiredAuthHeadersMock: vi.fn(),
  }));

vi.mock("server-only", () => ({}));

vi.mock("@/auth.config", () => ({
  auth: authMock,
}));

vi.mock("./server-auth", () => ({
  getAuthHeadersIfAvailable: getAuthHeadersIfAvailableMock,
  getRequiredAuthHeaders: getRequiredAuthHeadersMock,
}));

import { getAuthHeaders, getRouteAuthHeaders } from "./auth-headers";

describe("getAuthHeaders", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("forwards the restored session and requested header options", async () => {
    // Given
    authMock.mockResolvedValue({
      accessToken: "access-token",
      error: "RefreshAccessTokenError",
    });
    const options = { contentType: true };

    // When
    await getAuthHeaders(options);

    // Then
    expect(getRequiredAuthHeadersMock).toHaveBeenCalledWith(
      "access-token",
      options,
      "RefreshAccessTokenError",
    );
  });

  it("returns no route headers for a terminal session", async () => {
    // Given
    authMock.mockResolvedValue({
      accessToken: "stale-access-token",
      error: "RefreshAccessTokenError",
    });
    getAuthHeadersIfAvailableMock.mockReturnValue(null);

    // When
    const result = await getRouteAuthHeaders();

    // Then
    expect(result).toBeNull();
    expect(getAuthHeadersIfAvailableMock).toHaveBeenCalledWith(
      "stale-access-token",
      undefined,
      "RefreshAccessTokenError",
    );
    expect(getRequiredAuthHeadersMock).not.toHaveBeenCalled();
  });
});
