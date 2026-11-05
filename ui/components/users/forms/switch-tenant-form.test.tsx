import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SwitchTenantForm } from "./switch-tenant-form";

const { mockReloadPage, mockSwitchTenant, mockToast, mockUpdate } = vi.hoisted(
  () => ({
    mockReloadPage: vi.fn(),
    mockSwitchTenant: vi.fn(),
    mockToast: vi.fn(),
    mockUpdate: vi.fn(),
  }),
);

vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: mockUpdate }),
}));

vi.mock("@/actions/users/tenants", () => ({
  switchTenant: mockSwitchTenant,
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: mockToast }),
}));

vi.mock("@/lib/navigation", () => ({
  reloadPage: mockReloadPage,
}));

describe("SwitchTenantForm", () => {
  const setIsOpen = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

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

  it("shows an error when the session cannot apply the tenant switch", async () => {
    // Given
    const user = userEvent.setup();
    mockSwitchTenant.mockResolvedValue({
      success: true,
      accessToken: "switched-access-token",
      refreshToken: "switched-refresh-token",
    });
    mockUpdate.mockResolvedValue({ error: "TenantSwitchError" });
    render(<SwitchTenantForm tenantId="test-uuid" setIsOpen={setIsOpen} />);

    // When
    await user.click(screen.getByRole("button", { name: /confirm/i }));

    // Then
    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: "Unable to switch organization. Please try again.",
      }),
    );
    expect(mockReloadPage).not.toHaveBeenCalled();
  });

  it("reloads after the session applies the tenant switch", async () => {
    // Given
    const user = userEvent.setup();
    mockSwitchTenant.mockResolvedValue({
      success: true,
      accessToken: "switched-access-token",
      refreshToken: "switched-refresh-token",
    });
    mockUpdate.mockResolvedValue({
      expires: "2026-12-31T23:59:59.999Z",
    });
    render(<SwitchTenantForm tenantId="test-uuid" setIsOpen={setIsOpen} />);

    // When
    await user.click(screen.getByRole("button", { name: /confirm/i }));

    // Then
    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith({
        title: "Organization switched",
        description: "The page will reload to apply the change.",
      }),
    );
    expect(mockReloadPage).toHaveBeenCalledOnce();
  });
});
