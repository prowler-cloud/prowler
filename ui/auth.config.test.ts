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
