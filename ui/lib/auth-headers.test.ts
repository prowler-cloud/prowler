import { beforeEach, describe, expect, it, vi } from "vitest";

const { authMock, getRequiredAuthHeadersMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  getRequiredAuthHeadersMock: vi.fn(),
}));

vi.mock("server-only", () => ({}));

vi.mock("@/auth.config", () => ({
  auth: authMock,
}));

vi.mock("./server-auth", () => ({
  getRequiredAuthHeaders: getRequiredAuthHeadersMock,
}));

import { getAuthHeaders } from "./auth-headers";

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
});
