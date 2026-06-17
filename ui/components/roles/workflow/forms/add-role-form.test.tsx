import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AddRoleForm } from "./add-role-form";

const routerMocks = vi.hoisted(() => ({
  push: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => routerMocks,
}));

vi.mock("@/actions/roles/roles", () => ({
  addRole: vi.fn(),
}));

vi.mock("@/lib", () => ({
  cn: (...classes: Array<string | false | null | undefined>) =>
    classes.filter(Boolean).join(" "),
  getErrorMessage: (error: unknown) => String(error),
  permissionFormFields: [
    {
      field: "manage_users",
      label: "Invite and Manage Users",
      description:
        "Allows inviting new users and managing existing user details",
    },
    {
      field: "manage_account",
      label: "Manage Account",
      description: "Provides access to account settings and RBAC configuration",
    },
    {
      field: "unlimited_visibility",
      label: "Unlimited Visibility",
      description:
        "Provides complete visibility across all the providers and its related resources",
    },
    {
      field: "manage_providers",
      label: "Manage Providers",
      description:
        "Allows configuration and management of provider connections",
    },
    {
      field: "manage_integrations",
      label: "Manage Integrations",
      description:
        "Allows configuration and management of third-party integrations",
    },
    {
      field: "manage_scans",
      label: "Manage Scans",
      description: "Allows launching and configuring scans security scans",
    },
    {
      field: "manage_alerts",
      label: "Manage Alerts",
      description: "Allows creating and managing custom alerts",
    },
    {
      field: "manage_billing",
      label: "Manage Billing",
      description: "Provides access to billing settings and invoices",
    },
  ],
}));

vi.mock("@/components/shadcn/select/enhanced-multi-select", () => ({
  EnhancedMultiSelect: () => <div data-testid="group-select" />,
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: vi.fn() }),
}));

describe("AddRoleForm", () => {
  afterEach(() => {
    routerMocks.push.mockClear();
    vi.unstubAllEnvs();
  });

  it("shows Manage Alerts in Prowler Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");

    // When
    render(<AddRoleForm groups={[]} />);

    // Then
    expect(screen.getByText("Manage Alerts")).toBeInTheDocument();
    expect(screen.getByText("Manage Billing")).toBeInTheDocument();
  });

  it("hides Manage Alerts outside Prowler Cloud", () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    render(<AddRoleForm groups={[]} />);

    // Then
    expect(screen.queryByText("Manage Alerts")).not.toBeInTheDocument();
    expect(screen.queryByText("Manage Billing")).not.toBeInTheDocument();
  });

  it("navigates back to roles when cancel is clicked", async () => {
    // Given
    const user = userEvent.setup();
    render(<AddRoleForm groups={[]} />);

    // When
    await user.click(screen.getByRole("button", { name: /cancel/i }));

    // Then
    expect(routerMocks.push).toHaveBeenCalledWith("/roles");
  });
});
