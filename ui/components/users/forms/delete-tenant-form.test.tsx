import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { logOut } from "@/actions/auth";
import { deleteTenant } from "@/actions/users/tenants";

import { DeleteTenantForm } from "./delete-tenant-form";

const mockUpdate = vi.fn();
vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: mockUpdate }),
}));

vi.mock("@/auth.config", () => ({
  auth: vi.fn(),
}));

vi.mock("@/actions/users/tenants", () => ({
  deleteTenant: vi.fn(),
  switchTenant: vi.fn(),
  switchThenDeleteTenant: vi.fn(),
}));

vi.mock("@/actions/auth", () => ({
  logOut: vi.fn(),
}));

const mockToast = vi.fn();
vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: mockToast }),
}));

const baseProps = {
  tenantId: "tenant-1",
  tenantName: "My Organization",
  isActiveTenant: false,
  isLastTenant: false,
  availableTenants: [{ id: "tenant-2", name: "Other Org" }],
  setIsOpen: vi.fn(),
};

describe("DeleteTenantForm", () => {
  it("renders confirmation input and form buttons", () => {
    render(<DeleteTenantForm {...baseProps} />);
    expect(screen.getByPlaceholderText("My Organization")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /delete/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
  });

  it("submit button is disabled until name matches exactly", async () => {
    const user = userEvent.setup();
    render(<DeleteTenantForm {...baseProps} />);

    const submitBtn = screen.getByRole("button", { name: /delete/i });
    expect(submitBtn).toBeDisabled();

    await user.type(screen.getByPlaceholderText("My Organization"), "My Org");
    expect(submitBtn).toBeDisabled();

    await user.clear(screen.getByPlaceholderText("My Organization"));
    await user.type(
      screen.getByPlaceholderText("My Organization"),
      "My Organization",
    );
    expect(submitBtn).toBeEnabled();
  });

  it("is case-sensitive — lowercase does not match", async () => {
    const user = userEvent.setup();
    render(<DeleteTenantForm {...baseProps} />);

    await user.type(
      screen.getByPlaceholderText("My Organization"),
      "my organization",
    );
    expect(screen.getByRole("button", { name: /delete/i })).toBeDisabled();
  });

  it("does not show target tenant select for non-active tenant", () => {
    render(<DeleteTenantForm {...baseProps} />);
    expect(
      screen.queryByText(/switch to after deletion/i),
    ).not.toBeInTheDocument();
  });

  it("shows target tenant select for active tenant", () => {
    render(<DeleteTenantForm {...baseProps} isActiveTenant={true} />);
    expect(screen.getByText(/switch to after deletion/i)).toBeInTheDocument();
  });

  it("closes modal on cancel click", async () => {
    const user = userEvent.setup();
    render(<DeleteTenantForm {...baseProps} />);
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(baseProps.setIsOpen).toHaveBeenCalledWith(false);
  });

  it("shows last-tenant warning and no target select when isLastTenant", () => {
    render(
      <DeleteTenantForm
        {...baseProps}
        isActiveTenant={true}
        isLastTenant={true}
        availableTenants={[]}
      />,
    );
    expect(screen.getByText(/close your session/i)).toBeInTheDocument();
    expect(
      screen.queryByText(/switch to after deletion/i),
    ).not.toBeInTheDocument();
  });

  it("last-tenant submit enables with name only, then deletes and signs out", async () => {
    const user = userEvent.setup();
    vi.mocked(deleteTenant).mockResolvedValue({ success: true });

    render(
      <DeleteTenantForm
        {...baseProps}
        isActiveTenant={true}
        isLastTenant={true}
        availableTenants={[]}
      />,
    );

    const submitBtn = screen.getByRole("button", { name: /delete/i });
    expect(submitBtn).toBeDisabled();

    await user.type(
      screen.getByPlaceholderText("My Organization"),
      "My Organization",
    );
    expect(submitBtn).toBeEnabled();

    await user.click(submitBtn);

    await waitFor(() => {
      expect(deleteTenant).toHaveBeenCalled();
      expect(logOut).toHaveBeenCalled();
    });
  });

  it("last-tenant submit does not sign out when delete fails", async () => {
    const user = userEvent.setup();
    vi.mocked(deleteTenant).mockResolvedValue({ error: "Delete failed" });

    render(
      <DeleteTenantForm
        {...baseProps}
        isActiveTenant={true}
        isLastTenant={true}
        availableTenants={[]}
      />,
    );

    await user.type(
      screen.getByPlaceholderText("My Organization"),
      "My Organization",
    );
    await user.click(screen.getByRole("button", { name: /delete/i }));

    await waitFor(() => {
      expect(deleteTenant).toHaveBeenCalled();
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      );
    });
    expect(logOut).not.toHaveBeenCalled();
  });
});
