import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { CreateTenantForm } from "./create-tenant-form";

const mockUpdate = vi.fn();
vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: mockUpdate }),
}));

vi.mock("@/auth.config", () => ({
  auth: vi.fn(),
}));

vi.mock("@/actions/users/tenants", () => ({
  createTenant: vi.fn(),
  switchTenant: vi.fn(),
}));

const mockToast = vi.fn();
vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: mockToast }),
}));

describe("CreateTenantForm", () => {
  const setIsOpen = vi.fn();

  it("renders name input and form buttons", () => {
    render(<CreateTenantForm setIsOpen={setIsOpen} />);
    expect(screen.getByLabelText(/organization name/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
  });

  it("closes modal on cancel click", async () => {
    const user = userEvent.setup();
    render(<CreateTenantForm setIsOpen={setIsOpen} />);
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(setIsOpen).toHaveBeenCalledWith(false);
  });
});
