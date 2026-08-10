import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { deleteTenantThenSignOut } from "@/actions/users/tenants";

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
  deleteTenantThenSignOut: vi.fn(),
  switchTenant: vi.fn(),
  switchThenDeleteTenant: vi.fn(),
}));

const mockToast = vi.fn();
vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
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

  it("last-tenant submit enables with name only and calls the delete-and-sign-out action", async () => {
    const user = userEvent.setup();
    // The action redirects server-side on success, so the promise never
    // resolves with a value in the real flow; a NEXT_REDIRECT rejection is
    // the closest observable behavior.
    vi.mocked(deleteTenantThenSignOut).mockRejectedValue({
      digest: "NEXT_REDIRECT;replace;/sign-in;303;",
    });

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
      expect(deleteTenantThenSignOut).toHaveBeenCalled();
    });
    // A redirect is not a failure: no error toast
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive" }),
    );
  });

  it("last-tenant submit shows error and re-enables when delete fails", async () => {
    const user = userEvent.setup();
    vi.mocked(deleteTenantThenSignOut).mockResolvedValue({
      error: "Delete failed",
    });

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
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          description: "Delete failed",
        }),
      );
    });
    // Submitting state is reset so the user is not stuck on a disabled button
    expect(screen.getByRole("button", { name: /delete/i })).toBeEnabled();
  });

  it("last-tenant submit recovers when the action call itself fails", async () => {
    const user = userEvent.setup();
    vi.mocked(deleteTenantThenSignOut).mockRejectedValue(
      new Error("network error"),
    );

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
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      );
    });
    expect(screen.getByRole("button", { name: /delete/i })).toBeEnabled();
  });
});
