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

// Access token whose "exp" claim is in the past (2001), so the JWT callback
// takes the refresh branch.
const EXPIRED_ACCESS_TOKEN =
  "header.eyJzdWIiOiJ1c2VyLTEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMSIsImV4cCI6MTAwMDAwMDAwMH0.signature";
// Access token whose "exp" claim is far in the future (2100).
const ROTATED_ACCESS_TOKEN =
  "header.eyJzdWIiOiJ1c2VyLTEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMSIsImV4cCI6NDEwMjQ0NDgwMH0.signature";

const refreshResponse = (accessToken: string, refreshToken: string) => ({
  ok: true,
  status: 200,
  json: async () => ({
    data: {
      type: "tokens-refresh",
      attributes: { access: accessToken, refresh: refreshToken },
    },
  }),
});

const blacklistedRefreshResponse = () => ({
  ok: false,
  status: 401,
  json: async () => ({
    errors: [{ detail: "Token is blacklisted", code: "token_not_valid" }],
  }),
});

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
});

describe("authConfig token refresh with rotated refresh tokens", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  // The rotated-pair cache is module scoped, so each test needs its own refresh
  // token to stay independent.
  const expiredToken = (refreshToken: string) => ({
    accessToken: EXPIRED_ACCESS_TOKEN,
    refreshToken,
    tenant_id: "tenant-1",
    user: {
      name: "Tenant User",
      email: "tenant@example.com",
      dateJoined: "2026-01-01",
      permissions: RESTRICTED_PERMISSIONS,
    },
  });

  it("should reuse the rotated token pair when the previous refresh could not be persisted", async () => {
    // Given a refresh that succeeds but whose cookie is never written (Server
    // Component render), the API blacklists "refresh-token-1" on rotation, so a
    // second refresh with the same stale cookie would be rejected.
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        refreshResponse(ROTATED_ACCESS_TOKEN, "refresh-token-2"),
      )
      .mockResolvedValueOnce(blacklistedRefreshResponse());
    vi.stubGlobal("fetch", fetchMock);
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");

    // When the same stale token is presented twice
    const firstResult = await jwtCallback({
      token: expiredToken("stale-cookie-refresh-token"),
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
      account: null,
    });
    const secondResult = await jwtCallback({
      token: expiredToken("stale-cookie-refresh-token"),
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
      account: null,
    });

    // Then the rotated pair is reused instead of burning a blacklisted token
    expect(firstResult).toMatchObject({
      accessToken: ROTATED_ACCESS_TOKEN,
      refreshToken: "refresh-token-2",
    });
    expect(secondResult).toMatchObject({
      accessToken: ROTATED_ACCESS_TOKEN,
      refreshToken: "refresh-token-2",
    });
    expect(secondResult.error).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("should still report a terminal error when the refresh token is genuinely rejected", async () => {
    // Given
    const fetchMock = vi.fn().mockResolvedValue(blacklistedRefreshResponse());
    vi.stubGlobal("fetch", fetchMock);
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");

    // When
    const result = await jwtCallback({
      token: expiredToken("rejected-refresh-token"),
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
      account: null,
    });

    // Then
    expect(result.error).toBe("RefreshAccessTokenError");
  });

  it("should retry against the API after a transient refresh failure", async () => {
    // Given a network failure followed by a healthy response
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("Network unreachable"))
      .mockResolvedValueOnce(
        refreshResponse(ROTATED_ACCESS_TOKEN, "retried-refresh-token"),
      );
    vi.stubGlobal("fetch", fetchMock);
    const jwtCallback = authConfig.callbacks?.jwt;
    if (!jwtCallback) throw new Error("JWT callback is not configured");

    // When
    const failedResult = await jwtCallback({
      token: expiredToken("transient-refresh-token"),
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
      account: null,
    });
    const retriedResult = await jwtCallback({
      token: expiredToken("transient-refresh-token"),
      user: {} as Parameters<typeof jwtCallback>[0]["user"],
      account: null,
    });

    // Then the failure is not cached and the retry recovers the session
    expect(failedResult.error).toBe("RefreshAccessTokenError");
    expect(retriedResult).toMatchObject({
      accessToken: ROTATED_ACCESS_TOKEN,
      refreshToken: "retried-refresh-token",
    });
    expect(retriedResult.error).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
