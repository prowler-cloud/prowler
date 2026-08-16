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

import { createNewUser, getUserByMe } from "./auth";

const userMeResponse = (roleAttributes: Record<string, boolean>) => ({
  data: {
    type: "users",
    id: "019b1234-5678-7abc-9def-0123456789ab",
    attributes: {
      name: "Jane Doe",
      email: "jane@example.com",
      company_name: "Prowler",
      date_joined: "2026-01-01T00:00:00.000Z",
    },
  },
  included: [
    {
      type: "roles",
      id: "role-1",
      attributes: { name: "Cloud admin", ...roleAttributes },
    },
  ],
});

const mockUserMe = (roleAttributes: Record<string, boolean>) => {
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify(userMeResponse(roleAttributes)), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
};

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

  it("should forward attribution params when creating a user", async () => {
    // Given
    const apiResponse = {
      data: {
        type: "users",
        id: "019b1234-5678-7abc-9def-0123456789ab",
      },
    };
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify(apiResponse), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );

    // When
    const result = await createNewUser(
      {
        name: "Jane Doe",
        email: "jane@example.com",
        password: "TestPassword123!",
        confirmPassword: "TestPassword123!",
        company: "Prowler",
        termsAndConditions: undefined,
        isSamlMode: false,
      },
      {
        promo_code: "black-hat-2026",
        utm_source: "blackhat",
      },
    );

    // Then
    expect(result).toEqual(apiResponse);
    const requestUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(requestUrl.searchParams.get("promo_code")).toBe("black-hat-2026");
    expect(requestUrl.searchParams.get("utm_source")).toBe("blackhat");
  });

  it("should carry manage_lighthouse_ai_configuration into the session permissions", async () => {
    // Given
    mockUserMe({ manage_lighthouse_ai_configuration: true });

    // When
    const result = await getUserByMe("access-token");

    // Then
    expect(result.permissions.manage_lighthouse_ai_configuration).toBe(true);
  });

  it("should default manage_lighthouse_ai_configuration to false when the role omits it", async () => {
    // Given
    mockUserMe({ manage_users: true });

    // When
    const result = await getUserByMe("access-token");

    // Then
    expect(result.permissions.manage_lighthouse_ai_configuration).toBe(false);
    expect(result.permissions.manage_users).toBe(true);
  });
});
