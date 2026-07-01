import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SwitchTenantForm } from "./switch-tenant-form";

const mockUpdate = vi.fn();
vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: mockUpdate }),
}));

vi.mock("@/actions/users/tenants", () => ({
  switchTenant: vi.fn(),
}));

const mockToast = vi.fn();
vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: mockToast }),
}));

describe("SwitchTenantForm", () => {
  const setIsOpen = vi.fn();

  it("renders confirm and cancel buttons", () => {
    render(<SwitchTenantForm tenantId="test-uuid" setIsOpen={setIsOpen} />);

    expect(
      screen.getByRole("button", { name: /confirm/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
  });

  it("includes hidden tenantId input", () => {
    render(<SwitchTenantForm tenantId="test-uuid" setIsOpen={setIsOpen} />);

    const hiddenInput = document.querySelector(
      'input[name="tenantId"]',
    ) as HTMLInputElement;
    expect(hiddenInput).toBeTruthy();
    expect(hiddenInput.value).toBe("test-uuid");
  });

  it("closes modal on cancel click", async () => {
    const user = userEvent.setup();
    render(<SwitchTenantForm tenantId="test-uuid" setIsOpen={setIsOpen} />);

    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(setIsOpen).toHaveBeenCalledWith(false);
  });
});
