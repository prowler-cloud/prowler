import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { addRole } from "@/actions/roles/roles";

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
      field: "manage_lighthouse_ai_configuration",
      label: "Manage Lighthouse AI",
      description:
        "Allows configuring Lighthouse AI, including its provider credentials, default model and business context",
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

beforeAll(() => {
  class ResizeObserverMock {
    observe() {}
    unobserve() {}
    disconnect() {}
  }

  globalThis.ResizeObserver = ResizeObserverMock;
  window.ResizeObserver = ResizeObserverMock;
});

const submitRoleForm = async (
  user: ReturnType<typeof userEvent.setup>,
  { grantLighthouseAi }: { grantLighthouseAi: boolean },
) => {
  await user.type(screen.getByPlaceholderText("Enter role name"), "New role");

  if (grantLighthouseAi) {
    await user.click(
      screen.getByRole("checkbox", { name: "Manage Lighthouse AI" }),
    );
  }

  await user.click(screen.getByRole("button", { name: "Add Role" }));
};

const submittedFormData = () => {
  const formData = vi.mocked(addRole).mock.calls.at(-1)?.[0];
  if (!formData) throw new Error("addRole was not called");
  return formData;
};

describe("AddRoleForm", () => {
  afterEach(() => {
    routerMocks.push.mockClear();
    vi.mocked(addRole).mockClear();
    vi.unstubAllEnvs();
  });

  it("shows Manage Alerts in Prowler Cloud", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    render(<AddRoleForm groups={[]} />);

    // Then
    expect(screen.getByText("Manage Alerts")).toBeInTheDocument();
    expect(screen.getByText("Manage Lighthouse AI")).toBeInTheDocument();
    expect(screen.getByText("Manage Billing")).toBeInTheDocument();
  });

  it("hides Manage Alerts outside Prowler Cloud", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    render(<AddRoleForm groups={[]} />);

    // Then
    expect(screen.queryByText("Manage Alerts")).not.toBeInTheDocument();
    expect(screen.queryByText("Manage Lighthouse AI")).not.toBeInTheDocument();
    expect(screen.queryByText("Manage Billing")).not.toBeInTheDocument();
  });

  it("submits manage_lighthouse_ai_configuration when granted in Prowler Cloud", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();
    render(<AddRoleForm groups={[]} />);

    // When
    await submitRoleForm(user, { grantLighthouseAi: true });

    // Then
    expect(submittedFormData().get("manage_lighthouse_ai_configuration")).toBe(
      "true",
    );
  });

  it("submits manage_lighthouse_ai_configuration as false when not granted in Prowler Cloud", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();
    render(<AddRoleForm groups={[]} />);

    // When
    await submitRoleForm(user, { grantLighthouseAi: false });

    // Then
    expect(submittedFormData().get("manage_lighthouse_ai_configuration")).toBe(
      "false",
    );
  });

  it("omits manage_lighthouse_ai_configuration from the submission outside Prowler Cloud", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    const user = userEvent.setup();
    render(<AddRoleForm groups={[]} />);

    // When
    await submitRoleForm(user, { grantLighthouseAi: false });

    // Then
    expect(submittedFormData().has("manage_lighthouse_ai_configuration")).toBe(
      false,
    );
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

  it("shows a subtle inline Unlimited Visibility description", () => {
    // Given / When
    render(<AddRoleForm groups={[]} />);

    // Then
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Checking the box below grants visibility into every provider: resources, findings, scans, and compliance results, regardless of the provider groups selected.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/required to use the Jira integration/i),
    ).toHaveProperty("tagName", "STRONG");
    expect(
      screen.getByRole("link", { name: /learn more about provider groups/i }),
    ).toHaveAttribute(
      "href",
      "https://docs.prowler.com/user-guide/tutorials/prowler-app-rbac#provider-groups",
    );
    expect(
      screen.queryByRole("heading", { name: "Unlimited Visibility" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(
        /does not grant admin actions such as managing users, providers, scans, integrations, billing, or alerts/i,
      ),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(
        /enable it only for roles that need organization-wide security visibility/i,
      ),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(
        /manage providers enables unlimited visibility in this form because provider administration needs organization-wide provider-group context/i,
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
    render(<AddRoleForm groups={[{ id: "group-1", name: "Production" }]} />);

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
      screen.getByText(/checking the box below grants visibility/i),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("group-select")).not.toBeInTheDocument();
    expect(
      screen.queryByText(/select the groups this role will have access to/i),
    ).not.toBeInTheDocument();
  });

  it("does not force Unlimited Visibility when Manage Providers is selected", async () => {
    // Given
    const user = userEvent.setup();
    render(<AddRoleForm groups={[]} />);

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
    render(<AddRoleForm groups={[]} />);

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
    render(<AddRoleForm groups={[]} />);

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
    render(<AddRoleForm groups={[]} />);

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

  it("does not show extra Manage Providers guidance for explicitly enabled Unlimited Visibility", async () => {
    // Given
    const user = userEvent.setup();
    render(<AddRoleForm groups={[]} />);

    // When
    await user.click(
      screen.getByRole("checkbox", {
        name: "Enable Unlimited Visibility for this role",
      }),
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Manage Providers" }),
    );

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
});
