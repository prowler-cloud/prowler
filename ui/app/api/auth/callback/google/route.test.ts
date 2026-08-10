import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, signInMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  signInMock: vi.fn(),
}));

vi.mock("@/auth.config", () => ({
  signIn: signInMock,
}));

vi.mock("@/lib/helper", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  baseUrl: "https://app.example.com",
}));

import { GET } from "./route";

describe("Google OAuth callback route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    signInMock.mockResolvedValue({});
  });

  it("should forward callback attribution to the token exchange", async () => {
    // Given
    fetchMock.mockResolvedValue(
      Response.json({
        data: {
          attributes: {
            access: "access-token",
            refresh: "refresh-token",
          },
        },
      }),
    );
    const state = encodeURIComponent(
      "/?promo_code=black-hat-2026&utm_source=blackhat",
    );
    const request = new Request(
      `https://app.example.com/api/auth/callback/google?code=oauth-code&state=${state}`,
    );

    // When
    await GET(request);

    // Then
    const body = new URLSearchParams(fetchMock.mock.calls[0][1].body);
    expect(body.get("code")).toBe("oauth-code");
    expect(body.get("promo_code")).toBe("black-hat-2026");
    expect(body.get("utm_source")).toBe("blackhat");
  });
});
