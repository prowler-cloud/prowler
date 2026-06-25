import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { PROVIDER_WIZARD_MODE } from "@/types/provider-wizard";

import { ProviderWizardModal } from "./provider-wizard-modal";

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: vi.fn(),
  }),
}));

vi.mock("@/hooks/use-scroll-hint", () => ({
  useScrollHint: () => ({
    containerRef: vi.fn(),
    sentinelRef: vi.fn(),
    showScrollHint: false,
  }),
}));

vi.mock("@/components/providers/wizard/steps/connect-step", () => ({
  ConnectStep: () => <div>Connect step</div>,
}));

vi.mock("@/components/providers/wizard/steps/credentials-step", () => ({
  CredentialsStep: ({ onNext }: { onNext: () => void }) => (
    <div>
      <div>Credentials step</div>
      <button type="button" onClick={onNext}>
        Continue to validate connection
      </button>
    </div>
  ),
}));

vi.mock("@/components/providers/wizard/steps/test-connection-step", () => ({
  TestConnectionStep: ({ onSuccess }: { onSuccess: () => void }) => (
    <div>
      <div>Test connection step</div>
      <button type="button" onClick={onSuccess}>
        Check connection
      </button>
    </div>
  ),
}));

vi.mock("@/components/providers/wizard/steps/launch-step", () => ({
  LaunchStep: () => <div>Launch step</div>,
}));

vi.mock("@/components/providers/organizations/org-setup-form", () => ({
  OrgSetupForm: () => <div>Organization setup</div>,
}));

vi.mock("@/components/providers/organizations/org-account-selection", () => ({
  OrgAccountSelection: () => <div>Organization account selection</div>,
}));

vi.mock("@/components/providers/organizations/org-launch-scan", () => ({
  OrgLaunchScan: () => <div>Organization launch scan</div>,
}));

describe("ProviderWizardModal", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    useProviderWizardStore.getState().reset();
    useOrgSetupStore.getState().reset();
  });

  it("provides an accessible dialog description without requiring visible helper text", () => {
    // Given
    const onOpenChange = vi.fn();

    // When
    render(<ProviderWizardModal open onOpenChange={onOpenChange} />);

    // Then
    const dialog = screen.getByRole("dialog", { name: /adding a provider/i });
    const descriptionId = dialog.getAttribute("aria-describedby");

    expect(descriptionId).toBeTruthy();
    expect(document.getElementById(descriptionId ?? "")).toHaveTextContent(
      /connect or update a provider/i,
    );
  });

  it("shows the launch progress step when update mode reaches launch", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenChange = vi.fn();

    render(
      <ProviderWizardModal
        open
        onOpenChange={onOpenChange}
        initialData={{
          providerId: "provider-1",
          providerType: "aws",
          providerUid: "111111111111",
          providerAlias: "production",
          secretId: "secret-1",
          mode: PROVIDER_WIZARD_MODE.UPDATE,
        }}
      />,
    );
    expect(await screen.findByText("Credentials step")).toBeVisible();

    // When
    await user.click(
      screen.getByRole("button", { name: /continue to validate connection/i }),
    );
    await user.click(
      await screen.findByRole("button", { name: /check connection/i }),
    );

    // Then
    expect(screen.getByText("Launch step")).toBeVisible();
    expect(screen.getByText("Launch Scan")).toBeVisible();
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });
});
