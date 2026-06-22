import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
}));

vi.mock("next-auth", () => ({
  AuthError: class AuthError extends Error {},
}));

vi.mock("@/auth.config", () => ({
  signIn: vi.fn(),
  signOut: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
}));

vi.mock("@/lib/sentry-breadcrumbs", () => ({
  addAuthEvent: vi.fn(),
}));

import { createNewUser } from "./auth";

describe("auth actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("should preserve HTTP status when user creation fails", async () => {
    // Given
    const apiResponse = {
      errors: [
        {
          status: "400",
          code: "invalid",
          detail: "Invalid invitation code.",
          source: { pointer: "/data/attributes/invitation_token" },
        },
      ],
    };
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify(apiResponse), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }),
    );

    // When
    const result = await createNewUser({
      name: "Jane Doe",
      email: "jane@example.com",
      password: "TestPassword123!",
      confirmPassword: "TestPassword123!",
      company: "Prowler",
      invitationToken: "invitation-token",
      termsAndConditions: undefined,
      isSamlMode: false,
    });

    // Then
    expect(result).toEqual({ ...apiResponse, status: 400 });
  });
});
