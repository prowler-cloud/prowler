import { afterEach, describe, expect, it, vi } from "vitest";

import type { RolePermissionAttributes } from "@/types/users";

import { getRolePermissions } from "./permissions";

const attributes = {
  manage_users: false,
  manage_account: false,
  manage_providers: false,
  manage_scans: false,
  manage_integrations: false,
  manage_billing: false,
  manage_alerts: true,
  unlimited_visibility: false,
} satisfies RolePermissionAttributes;

describe("getRolePermissions", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("includes Manage Alerts in Prowler Cloud when role attributes provide it", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    const permissions = getRolePermissions(attributes);

    // Then
    expect(permissions).toContainEqual({
      key: "manage_alerts",
      label: "Manage Alerts",
      enabled: true,
    });
  });

  it("hides Manage Alerts outside Prowler Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    const permissions = getRolePermissions(attributes);

    // Then
    expect(
      permissions.some((permission) => permission.key === "manage_alerts"),
    ).toBe(false);
  });
});
