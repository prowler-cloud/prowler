import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

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

beforeAll(() => {
  class ResizeObserverMock {
    observe() {}
    unobserve() {}
    disconnect() {}
  }

  globalThis.ResizeObserver = ResizeObserverMock;
  window.ResizeObserver = ResizeObserverMock;
});

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

  it("shows the subtle Unlimited Visibility description inside Visibility", () => {
    // Given / When
    renderEditRoleForm();

    // Then
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.getByText(/tenant-wide visibility setting/i),
    ).toHaveTextContent(
      /grants visibility into every provider, account, resource, finding, scan, and compliance result.*required to use the Jira integration/i,
    );
    expect(
      screen.getByText(/required to use the Jira integration/i),
    ).toHaveProperty("tagName", "STRONG");
    expect(
      screen.queryByText(
        /manage providers enables unlimited visibility in this form because provider administration needs tenant-wide provider-group context/i,
      ),
    ).not.toBeInTheDocument();

    const visibilityHeading = screen.getByText("Visibility");
    const unlimitedVisibilityCheckbox = screen.getByRole("checkbox", {
      name: "Enable Unlimited Visibility for this role",
    });

    expect(
      visibilityHeading.compareDocumentPosition(unlimitedVisibilityCheckbox) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("keeps the Visibility section and hides only groups when Unlimited Visibility is enabled", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <EditRoleForm
        roleId="role-1"
        roleData={roleData()}
        groups={[{ id: "group-1", name: "Production" }]}
      />,
    );

    // When
    await user.click(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    );

    // Then
    expect(screen.getByText("Visibility")).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    ).toBeChecked();
    expect(
      screen.getByText(/tenant-wide visibility setting/i),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("group-select")).not.toBeInTheDocument();
    expect(
      screen.queryByText(/select the groups this role will have access to/i),
    ).not.toBeInTheDocument();
  });

  it("does not force Unlimited Visibility when Manage Providers is selected", async () => {
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
    ).not.toBeChecked();
    expect(
      screen.queryByText(
        /Manage Providers is selected, so Unlimited Visibility stays enabled in this form/i,
      ),
    ).not.toBeInTheDocument();
  });

  it("does not force Unlimited Visibility when granting all admin permissions", async () => {
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
    ).not.toBeChecked();
  });

  it("keeps Unlimited Visibility user-controlled when Manage Providers is selected", async () => {
    // Given
    const user = userEvent.setup();
    renderEditRoleForm();

    // When
    await user.click(
      screen.getByRole("checkbox", { name: "Manage Providers" }),
    );
    await user.click(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    );
    await user.click(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    );

    // Then
    expect(
      screen.getByRole("checkbox", { name: "Manage Providers" }),
    ).toBeChecked();
    expect(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    ).not.toBeChecked();
    expect(screen.getByTestId("group-select")).toBeInTheDocument();
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

  it("does not show extra Manage Providers guidance", () => {
    // Given / When
    renderEditRoleForm({ manageProviders: true, unlimitedVisibility: true });

    // Then
    expect(
      screen.queryByText(
        /Manage Providers is selected, so Unlimited Visibility stays enabled in this form/i,
      ),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/remove this automatic visibility grant/i),
    ).not.toBeInTheDocument();
  });

  it("keeps existing inconsistent Manage Providers and Unlimited Visibility values on initial render", () => {
    // Given / When
    renderEditRoleForm({ manageProviders: true, unlimitedVisibility: false });

    // Then
    expect(
      screen.getByRole("checkbox", { name: "Manage Providers" }),
    ).toBeChecked();
    const unlimitedVisibilityCheckbox = screen.getByRole("checkbox", {
      name: "Enable Unlimited Visibility for this role",
    });
    expect(unlimitedVisibilityCheckbox).not.toBeChecked();
    expect(unlimitedVisibilityCheckbox).toBeEnabled();
  });
});
