import { beforeEach, describe, expect, it, vi } from "vitest";

import { authConfig } from "./auth.config";
import type { RolePermissionAttributes } from "./types/users";

const { getUserByMeMock } = vi.hoisted(() => ({
  getUserByMeMock: vi.fn(),
}));

vi.mock("next-auth", () => ({
  default: vi.fn(() => ({
    signIn: vi.fn(),
    signOut: vi.fn(),
    auth: vi.fn(),
    handlers: {},
  })),
}));

vi.mock("next-auth/providers/credentials", () => ({
  default: vi.fn((config) => config),
}));

vi.mock("./actions/auth", () => ({
  getToken: vi.fn(),
  getUserByMe: getUserByMeMock,
}));

vi.mock("./lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
}));

const RESTRICTED_PERMISSIONS: RolePermissionAttributes = {
  manage_users: false,
  manage_account: false,
  manage_providers: false,
  manage_scans: false,
  manage_integrations: false,
  manage_alerts: false,
  unlimited_visibility: false,
};

const ELEVATED_PERMISSIONS: RolePermissionAttributes = {
  ...RESTRICTED_PERMISSIONS,
  manage_users: true,
  manage_scans: true,
};

const accessTokenFor = (tenantId: string, expiration: number) =>
  `header.${Buffer.from(
    JSON.stringify({ sub: "user-1", tenant_id: tenantId, exp: expiration }),
  ).toString("base64url")}.signature`;

const successfulRefreshResponse = (accessToken: string, refreshToken: string) =>
  new Response(
    JSON.stringify({
      data: {
        attributes: {
          access: accessToken,
          refresh: refreshToken,
        },
      },
    }),
    { status: 200 },
  );

const mockSuccessfulRefresh = (
  accessToken: string,
  refreshToken = "new-refresh-token",
) => {
  const fetchMock = vi
    .fn()
    .mockResolvedValue(successfulRefreshResponse(accessToken, refreshToken));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
};

describe("authConfig JWT callback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should load elevated tenant permissions after switching from a restricted tenant", async () => {
    // Given
    const accessToken =
      "header.eyJzdWIiOiJ1c2VyLTEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMiJ9.signature";
    getUserByMeMock.mockResolvedValue({
      name: "Tenant User",
      email: "tenant@example.com",
      company: "Tenant Company",
      dateJoined: "2026-01-01",
      permissions: ELEVATED_PERMISSIONS,
    });
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");

    // When
    const result = await jwtCallback({
      token: {
        accessToken: "restricted-access-token",
        refreshToken: "restricted-refresh-token",
        tenant_id: "tenant-1",
        user: {
          name: "Tenant User",
          email: "tenant@example.com",
          dateJoined: "2026-01-01",
          permissions: RESTRICTED_PERMISSIONS,
        },
      },
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
      trigger: "update",
      session: {
        accessToken,
        refreshToken: "elevated-refresh-token",
      },
    });

    // Then
    expect(getUserByMeMock).toHaveBeenCalledWith(accessToken);
    expect(result.user).toEqual({
      name: "Tenant User",
      email: "tenant@example.com",
      companyName: "Tenant Company",
      dateJoined: "2026-01-01",
      permissions: ELEVATED_PERMISSIONS,
    });
  });

  it("should load restricted tenant permissions after switching from an elevated tenant", async () => {
    // Given
    const accessToken =
      "header.eyJzdWIiOiJ1c2VyLTEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMSJ9.signature";
    getUserByMeMock.mockResolvedValue({
      name: "Tenant User",
      email: "tenant@example.com",
      company: "Tenant Company",
      dateJoined: "2026-01-01",
      permissions: RESTRICTED_PERMISSIONS,
    });
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");

    // When
    const result = await jwtCallback({
      token: {
        accessToken: "elevated-access-token",
        refreshToken: "elevated-refresh-token",
        tenant_id: "tenant-2",
        user: {
          name: "Tenant User",
          email: "tenant@example.com",
          dateJoined: "2026-01-01",
          permissions: ELEVATED_PERMISSIONS,
        },
      },
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
      trigger: "update",
      session: {
        accessToken,
        refreshToken: "restricted-refresh-token",
      },
    });

    // Then
    expect(getUserByMeMock).toHaveBeenCalledWith(accessToken);
    expect(result.accessToken).toBe(accessToken);
    expect(result.refreshToken).toBe("restricted-refresh-token");
    expect(result.tenant_id).toBe("tenant-1");
    expect(result.user).toMatchObject({
      permissions: RESTRICTED_PERMISSIONS,
    });
  });

  it("should report a tenant switch failure while preserving the current session", async () => {
    // Given
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    getUserByMeMock.mockRejectedValue(new Error("Temporary API failure"));
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");
    const sessionCallback = authConfig.callbacks?.session;
    if (!sessionCallback) throw new Error("Session callback is not configured");
    const currentToken = {
      accessToken: "current-access-token",
      refreshToken: "current-refresh-token",
      tenant_id: "tenant-1",
      user: {
        name: "Tenant User",
        email: "tenant@example.com",
        dateJoined: "2026-01-01",
        permissions: RESTRICTED_PERMISSIONS,
      },
    };

    // When
    const result = await jwtCallback({
      token: currentToken,
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
      trigger: "update",
      session: {
        accessToken:
          "header.eyJzdWIiOiJ1c2VyLTEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMiJ9.signature",
        refreshToken: "switched-refresh-token",
      },
    });
    if (!result) throw new Error("JWT callback cleared the current token");

    const session = await sessionCallback({
      session: {
        expires: "2026-12-31T23:59:59.999Z",
        user: { name: "Tenant User" },
      },
      token: result,
    } as Parameters<typeof sessionCallback>[0]);

    // Then
    expect(session).toMatchObject({
      error: "TenantSwitchError",
      accessToken: "current-access-token",
      refreshToken: "current-refresh-token",
      tenantId: "tenant-1",
      user: {
        permissions: RESTRICTED_PERMISSIONS,
      },
    });
    expect(result.error).toBeUndefined();
  });

  it("should replace restricted permissions after access token refresh", async () => {
    // Given
    const currentAccessToken = accessTokenFor("stale-tenant", 1);
    const newAccessToken = accessTokenFor("tenant-1", 4_102_444_800);
    mockSuccessfulRefresh(newAccessToken);
    getUserByMeMock.mockResolvedValue({
      name: "Tenant User",
      email: "tenant@example.com",
      company: "Tenant Company",
      dateJoined: "2026-01-01",
      permissions: ELEVATED_PERMISSIONS,
    });
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");

    // When
    const result = await jwtCallback({
      token: {
        accessToken: currentAccessToken,
        refreshToken: "current-refresh-token",
        user: {
          name: "Tenant User",
          email: "tenant@example.com",
          dateJoined: "2026-01-01",
          permissions: RESTRICTED_PERMISSIONS,
        },
      },
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
    });

    // Then
    expect(getUserByMeMock).toHaveBeenCalledWith(newAccessToken);
    expect(result).toMatchObject({
      accessToken: newAccessToken,
      refreshToken: "new-refresh-token",
      tenant_id: "tenant-1",
      user: {
        permissions: ELEVATED_PERMISSIONS,
      },
    });
    expect(result.error).toBeUndefined();
  });

  it("should replace elevated permissions when access is revoked", async () => {
    // Given
    const currentAccessToken = accessTokenFor("tenant-1", 1);
    const newAccessToken = accessTokenFor("tenant-1", 4_102_444_800);
    mockSuccessfulRefresh(newAccessToken);
    getUserByMeMock.mockResolvedValue({
      name: "Tenant User",
      email: "tenant@example.com",
      company: "Tenant Company",
      dateJoined: "2026-01-01",
      permissions: RESTRICTED_PERMISSIONS,
    });
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");

    // When
    const result = await jwtCallback({
      token: {
        accessToken: currentAccessToken,
        refreshToken: "current-refresh-token",
        user: {
          name: "Tenant User",
          email: "tenant@example.com",
          dateJoined: "2026-01-01",
          permissions: ELEVATED_PERMISSIONS,
        },
      },
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
    });

    // Then
    expect(getUserByMeMock).toHaveBeenCalledWith(newAccessToken);
    expect(result.user?.permissions).toEqual(RESTRICTED_PERMISSIONS);
    expect(result.error).toBeUndefined();
  });

  it("should keep the refreshed tokens and cached user when reloading the user fails", async () => {
    // Given
    const currentAccessToken = accessTokenFor("tenant-1", 1);
    const newAccessToken = accessTokenFor("tenant-1", 4_102_444_800);
    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => undefined);
    mockSuccessfulRefresh(newAccessToken);
    getUserByMeMock.mockRejectedValue(new Error("Temporary API failure"));
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");
    const sessionCallback = authConfig.callbacks?.session;
    if (!sessionCallback) throw new Error("Session callback is not configured");
    const cachedUser = {
      name: "Tenant User",
      email: "tenant@example.com",
      dateJoined: "2026-01-01",
      permissions: ELEVATED_PERMISSIONS,
    };

    // When
    const result = await jwtCallback({
      token: {
        accessToken: currentAccessToken,
        refreshToken: "current-refresh-token",
        user: cachedUser,
      },
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
    });
    const session = await sessionCallback({
      session: {
        expires: "2026-12-31T23:59:59.999Z",
        user: { name: "Tenant User" },
      },
      token: result,
    } as Parameters<typeof sessionCallback>[0]);

    // Then
    expect(session).toMatchObject({
      accessToken: newAccessToken,
      refreshToken: "new-refresh-token",
      tenantId: "tenant-1",
      user: cachedUser,
    });
    expect(result.error).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(
      "Error refreshing user after access token refresh:",
      expect.any(Error),
    );
  });

  it("should invalidate the session when access token refresh fails", async () => {
    // Given
    const currentAccessToken = accessTokenFor("tenant-1", 1);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(
            JSON.stringify({ errors: [{ detail: "Refresh token expired" }] }),
            { status: 401 },
          ),
        ),
    );
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");
    const sessionCallback = authConfig.callbacks?.session;
    if (!sessionCallback) throw new Error("Session callback is not configured");

    // When
    const result = await jwtCallback({
      token: {
        accessToken: currentAccessToken,
        refreshToken: "expired-refresh-token",
        user: {
          name: "Tenant User",
          email: "tenant@example.com",
          dateJoined: "2026-01-01",
          permissions: ELEVATED_PERMISSIONS,
        },
      },
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
    });
    const session = await sessionCallback({
      session: {
        expires: "2026-12-31T23:59:59.999Z",
        user: { name: "Tenant User" },
      },
      token: result,
    } as Parameters<typeof sessionCallback>[0]);

    // Then
    expect(getUserByMeMock).not.toHaveBeenCalled();
    expect(result.error).toBe("RefreshAccessTokenError");
    expect(session.error).toBe("RefreshAccessTokenError");
    expect(session.user).toBeUndefined();
    expect(session.accessToken).toBeUndefined();
    expect(session.refreshToken).toBeUndefined();
    expect(session.tenantId).toBeUndefined();
  });

  it("should deduplicate concurrent token and user refreshes", async () => {
    // Given
    const currentAccessToken = accessTokenFor("tenant-1", 1);
    const newAccessToken = accessTokenFor("tenant-1", 4_102_444_800);
    const fetchMock = mockSuccessfulRefresh(newAccessToken);
    getUserByMeMock.mockResolvedValue({
      name: "Tenant User",
      email: "tenant@example.com",
      company: "Tenant Company",
      dateJoined: "2026-01-01",
      permissions: ELEVATED_PERMISSIONS,
    });
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");
    const currentToken = {
      accessToken: currentAccessToken,
      refreshToken: "shared-refresh-token",
      user: {
        name: "Tenant User",
        email: "tenant@example.com",
        dateJoined: "2026-01-01",
        permissions: RESTRICTED_PERMISSIONS,
      },
    };

    // When
    const [firstResult, secondResult] = await Promise.all([
      jwtCallback({
        token: { ...currentToken },
        user: {} as Parameters<typeof jwtCallback>[0]["user"],
      }),
      jwtCallback({
        token: { ...currentToken },
        user: {} as Parameters<typeof jwtCallback>[0]["user"],
      }),
    ]);

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(getUserByMeMock).toHaveBeenCalledTimes(1);
    expect(firstResult).toEqual(secondResult);
    expect(firstResult.user?.permissions).toEqual(ELEVATED_PERMISSIONS);
  });

  it("should retry reloading the user on the next token rotation", async () => {
    // Given
    const currentAccessToken = accessTokenFor("tenant-1", 1);
    const firstAccessToken = accessTokenFor("tenant-1", 1);
    const secondAccessToken = accessTokenFor("tenant-1", 4_102_444_800);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        successfulRefreshResponse(
          firstAccessToken,
          "first-rotated-refresh-token",
        ),
      )
      .mockResolvedValueOnce(
        successfulRefreshResponse(
          secondAccessToken,
          "second-rotated-refresh-token",
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    getUserByMeMock
      .mockRejectedValueOnce(new Error("Temporary API failure"))
      .mockResolvedValueOnce({
        name: "Tenant User",
        email: "tenant@example.com",
        company: "Tenant Company",
        dateJoined: "2026-01-01",
        permissions: RESTRICTED_PERMISSIONS,
      });
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");

    // When
    const firstResult = await jwtCallback({
      token: {
        accessToken: currentAccessToken,
        refreshToken: "current-refresh-token",
        user: {
          name: "Tenant User",
          email: "tenant@example.com",
          dateJoined: "2026-01-01",
          permissions: ELEVATED_PERMISSIONS,
        },
      },
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
    });
    const secondResult = await jwtCallback({
      token: firstResult,
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
    });

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(getUserByMeMock).toHaveBeenNthCalledWith(1, firstAccessToken);
    expect(getUserByMeMock).toHaveBeenNthCalledWith(2, secondAccessToken);
    expect(firstResult.user?.permissions).toEqual(ELEVATED_PERMISSIONS);
    expect(secondResult).toMatchObject({
      accessToken: secondAccessToken,
      refreshToken: "second-rotated-refresh-token",
      user: { permissions: RESTRICTED_PERMISSIONS },
    });
  });
});
