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

describe("GitHub OAuth callback route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    signInMock.mockResolvedValue({});
  });

  it("redirects to sign-in with a specific error when self-registration is disabled", async () => {
    // Given
    fetchMock.mockResolvedValue(
      Response.json(
        { errors: [{ code: "self_registration_disabled", status: "403" }] },
        { status: 403 },
      ),
    );
    const request = new Request(
      "https://app.example.com/api/auth/callback/github?code=oauth-code",
    );

    // When
    const response = await GET(request);

    // Then
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://api.example.com/api/v1/tokens/github",
    );
    expect(response.headers.get("location")).toBe(
      "https://app.example.com/sign-in?error=SelfRegistrationDisabled",
    );
    expect(signInMock).not.toHaveBeenCalled();
  });

  it("keeps the generic failure for other token exchange errors", async () => {
    // Given
    fetchMock.mockResolvedValue(
      Response.json({ errors: [{ status: "400" }] }, { status: 400 }),
    );
    const request = new Request(
      "https://app.example.com/api/auth/callback/github?code=oauth-code",
    );

    // When
    const response = await GET(request);

    // Then
    expect(response.headers.get("location")).toBe(
      "https://app.example.com/sign-in?error=AuthenticationFailed",
    );
  });
});
