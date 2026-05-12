import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ScansLaunchSection } from "./scans-launch-section";

vi.mock("@/components/providers/wizard", () => ({
  ProviderWizardModal: ({ open }: { open: boolean }) =>
    open ? <div role="dialog">Provider wizard</div> : null,
}));

vi.mock("@/components/scans/launch-workflow", () => ({
  LaunchScanWorkflow: () => <div>Launch scan workflow</div>,
}));

vi.mock("@/components/scans/no-providers-connected", () => ({
  NoProvidersConnected: () => <div>No providers connected</div>,
}));

vi.mock("@/components/ui/custom/custom-banner", () => ({
  CustomBanner: ({ title }: { title: string }) => <div>{title}</div>,
}));

const connectedProvider = {
  providerId: "provider-1",
  alias: "Production",
  providerType: "aws",
  uid: "123456789012",
  connected: true,
};

describe("ScansLaunchSection", () => {
  it("should keep the provider wizard open when providers data refreshes after adding the first provider", async () => {
    // Given
    const user = userEvent.setup();
    const { rerender } = render(
      <ScansLaunchSection
        providers={[]}
        hasManageScansPermission
        thereIsNoProviders
        thereIsNoProvidersConnected
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", { name: /open add provider modal/i }),
    );
    rerender(
      <ScansLaunchSection
        providers={[connectedProvider]}
        hasManageScansPermission
        thereIsNoProviders={false}
        thereIsNoProvidersConnected={false}
      />,
    );

    // Then
    expect(screen.getByRole("dialog", { name: "" })).toHaveTextContent(
      "Provider wizard",
    );
    expect(screen.getByText("Launch scan workflow")).toBeInTheDocument();
  });
});
