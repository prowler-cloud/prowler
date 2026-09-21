import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AwsQuickOnboardingModal } from "./aws-quick-onboarding-modal";

vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: { tenantId: "tenant-abc" },
    status: "authenticated",
  }),
}));
vi.mock("@/actions/providers/providers", () => ({
  addProvider: vi.fn(),
  addCredentialsProvider: vi.fn(),
  updateCredentialsProvider: vi.fn(),
  updateProvider: vi.fn(),
}));
vi.mock("@/actions/scans", () => ({ scanOnDemand: vi.fn() }));
vi.mock("@/lib/provider-helpers", () => ({ testProviderConnection: vi.fn() }));

function renderModal() {
  const onOpenChange = vi.fn();
  const onBack = vi.fn();
  const onSelectOrganizations = vi.fn();
  render(
    <AwsQuickOnboardingModal
      open
      onOpenChange={onOpenChange}
      onBack={onBack}
      onSelectOrganizations={onSelectOrganizations}
    />,
  );
  return { onOpenChange, onBack, onSelectOrganizations };
}

describe("AwsQuickOnboardingModal", () => {
  beforeEach(() => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
  });

  it("renders its own two-step shell with the connection action", () => {
    renderModal();

    expect(
      screen.getByRole("dialog", { name: "Connect an AWS account" }),
    ).toBeVisible();
    expect(screen.getByText("Connect account")).toBeVisible();
    expect(screen.getByText("Name & launch")).toBeVisible();
    expect(screen.getByRole("textbox", { name: "IAM Role ARN" })).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Test connection" }),
    ).toBeDisabled();
  });

  it("returns to the provider selection from Back", async () => {
    const user = userEvent.setup();
    const { onOpenChange, onBack } = renderModal();

    await user.click(screen.getByRole("button", { name: "Back" }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onBack).toHaveBeenCalledOnce();
  });

  it("hands the organization tab off to the caller", async () => {
    const user = userEvent.setup();
    const { onOpenChange, onSelectOrganizations } = renderModal();

    await user.click(
      screen.getByRole("tab", { name: "Full AWS Organization" }),
    );

    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onSelectOrganizations).toHaveBeenCalledOnce();
  });
});
