import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ScansPageShell } from "./scans-page-shell";

const { pushMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/scans",
  useRouter: () => ({
    push: pushMock,
  }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/ui/entities", () => ({
  EntityInfo: ({
    entityAlias,
    entityId,
  }: {
    entityAlias?: string;
    entityId?: string;
  }) => <span>{entityAlias || entityId}</span>,
}));

vi.mock("./import-findings-modal", () => ({
  ImportFindingsModal: ({ open }: { open: boolean }) =>
    open ? <div role="dialog">Import findings</div> : null,
}));

vi.mock("./launch-scan-modal", () => ({
  LaunchScanModal: ({ open }: { open: boolean }) =>
    open ? <div role="dialog">Launch scan</div> : null,
}));

const providers = [
  {
    providerId: "provider-1",
    alias: "Production",
    providerType: "aws",
    uid: "123456789012",
    connected: true,
  },
];

describe("ScansPageShell", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.clearAllMocks();
  });

  it("disables imported scans entry points outside Cloud", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
    const user = userEvent.setup();

    render(
      <ScansPageShell providers={providers} hasManageScansPermission>
        <div>Scans table</div>
      </ScansPageShell>,
    );

    const importButton = screen.getByRole("button", {
      name: /import findings/i,
    });
    const importedTab = screen.getByRole("tab", { name: /imported scans/i });

    // When
    await user.click(importButton);
    await user.click(importedTab);
    await user.hover(importedTab);

    // Then
    expect(importButton).toBeDisabled();
    expect(importedTab).toHaveAttribute("aria-disabled", "true");
    expect(pushMock).not.toHaveBeenCalled();
    await waitFor(() => {
      expect(
        screen.getAllByText("Available in Prowler Cloud").length,
      ).toBeGreaterThan(1);
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
