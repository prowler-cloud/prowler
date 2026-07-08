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
    permission_state: "unlimited",
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

  it("displays the permission state as a badge", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    render(<RoleItem role={role} roleDetail={roleDetail} />);

    // Then
    expect(screen.getByText("unlimited")).toHaveClass("bg-bg-tag");
  });

  it("does not render the details toggle", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    render(<RoleItem role={role} roleDetail={roleDetail} />);

    // Then
    expect(
      screen.queryByRole("button", { name: /hide details/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /show details/i }),
    ).not.toBeInTheDocument();
  });
});
