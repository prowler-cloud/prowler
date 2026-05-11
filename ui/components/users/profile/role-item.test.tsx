import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RoleData, RoleDetail } from "@/types/users";

import { RoleItem } from "./role-item";

const role = {
  id: "role-1",
  type: "roles",
} satisfies RoleData;

const roleDetail = {
  id: "role-1",
  type: "roles",
  attributes: {
    name: "Cloud admin",
    manage_users: false,
    manage_account: false,
    manage_providers: false,
    manage_scans: false,
    manage_integrations: false,
    manage_billing: false,
    manage_alerts: true,
    unlimited_visibility: false,
  },
} satisfies RoleDetail;

describe("RoleItem", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("shows Manage Alerts in Prowler Cloud role details", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    render(<RoleItem role={role} roleDetail={roleDetail} />);

    // Then
    expect(screen.getByText("Manage Alerts")).toBeInTheDocument();
  });

  it("hides Manage Alerts outside Prowler Cloud role details", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    render(<RoleItem role={role} roleDetail={roleDetail} />);

    // Then
    expect(screen.queryByText("Manage Alerts")).not.toBeInTheDocument();
  });
});
