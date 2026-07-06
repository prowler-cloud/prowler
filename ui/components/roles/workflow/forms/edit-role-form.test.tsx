import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EditRoleForm } from "./edit-role-form";

const routerMocks = vi.hoisted(() => ({
  push: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => routerMocks,
}));

vi.mock("@/actions/roles/roles", () => ({
  updateRole: vi.fn(),
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

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

const roleData = ({
  manageProviders = false,
  unlimitedVisibility = false,
}: {
  manageProviders?: boolean;
  unlimitedVisibility?: boolean;
} = {}) => ({
  data: {
    attributes: {
      name: "Existing role",
      manage_users: false,
      manage_account: false,
      manage_providers: manageProviders,
      manage_integrations: false,
      manage_scans: false,
      unlimited_visibility: unlimitedVisibility,
      groups: [],
    },
    relationships: {
      provider_groups: {
        data: [],
      },
    },
  },
});

const renderEditRoleForm = (options?: Parameters<typeof roleData>[0]) =>
  render(
    <EditRoleForm roleId="role-1" roleData={roleData(options)} groups={[]} />,
  );

describe("EditRoleForm", () => {
  afterEach(() => {
    routerMocks.push.mockClear();
    vi.unstubAllEnvs();
  });

  it("enables Unlimited Visibility when Manage Providers is selected", async () => {
    // Given
    const user = userEvent.setup();
    renderEditRoleForm();

    // When
    await user.click(
      screen.getByRole("checkbox", { name: "Manage Providers" }),
    );

    // Then
    expect(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    ).toBeChecked();
    expect(
      screen.getByText(
        /Manage Providers is selected, so Unlimited Visibility stays enabled in this form/i,
      ),
    ).toBeInTheDocument();
  });

  it("enables Unlimited Visibility through Manage Providers when granting all admin permissions", async () => {
    // Given
    const user = userEvent.setup();
    renderEditRoleForm();

    // When
    await user.click(
      screen.getByRole("checkbox", { name: "Grant all admin permissions" }),
    );

    // Then
    expect(
      screen.getByRole("checkbox", { name: "Manage Providers" }),
    ).toBeChecked();
    expect(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    ).toBeChecked();
  });

  it("clears Unlimited Visibility when all admin permissions are toggled off after only auto-enabling it", async () => {
    // Given
    const user = userEvent.setup();
    renderEditRoleForm();

    // When
    await user.click(
      screen.getByRole("checkbox", { name: "Grant all admin permissions" }),
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Grant all admin permissions" }),
    );

    // Then
    expect(
      screen.getByRole("checkbox", { name: "Manage Providers" }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    ).not.toBeChecked();
  });

  it("keeps explicitly enabled Unlimited Visibility when all admin permissions are toggled off", async () => {
    // Given
    const user = userEvent.setup();
    renderEditRoleForm();

    // When
    await user.click(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Grant all admin permissions" }),
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Grant all admin permissions" }),
    );

    // Then
    expect(
      screen.getByRole("checkbox", { name: "Manage Providers" }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    ).toBeChecked();
  });

  it("does not describe clearing Manage Providers as removing existing Unlimited Visibility", async () => {
    // Given / When
    renderEditRoleForm({ manageProviders: true, unlimitedVisibility: true });

    // Then
    expect(
      await screen.findByText(
        /Manage Providers is selected, so Unlimited Visibility stays enabled in this form/i,
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/remove this automatic visibility grant/i),
    ).not.toBeInTheDocument();
  });
});
