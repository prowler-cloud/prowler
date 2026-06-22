import { act, render, screen, waitFor } from "@testing-library/react";
import type { ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

import { OrgLaunchScan } from "./org-launch-scan";

const { launchOrganizationScansMock, pushMock, toastMock } = vi.hoisted(() => ({
  launchOrganizationScansMock: vi.fn(),
  pushMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/scans/scans", () => ({
  launchOrganizationScans: launchOrganizationScansMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
}));

vi.mock("@/components/ui", () => ({
  ToastAction: ({ children, ...props }: ComponentProps<"button">) => (
    <button {...props}>{children}</button>
  ),
  useToast: () => ({
    toast: toastMock,
  }),
}));

describe("OrgLaunchScan", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    launchOrganizationScansMock.mockReset();
    pushMock.mockReset();
    toastMock.mockReset();
    useOrgSetupStore.getState().reset();
    useOrgSetupStore
      .getState()
      .setOrganization("org-1", "My Organization", "o-abc123def4");
    useOrgSetupStore.getState().setCreatedProviderIds(["provider-1"]);
  });

  it("shows a success toast with an action linking to scans", async () => {
    // Given
    launchOrganizationScansMock.mockResolvedValue({ successCount: 1 });
    const onFooterChange = vi.fn();

    render(
      <OrgLaunchScan
        onClose={vi.fn()}
        onBack={vi.fn()}
        onFooterChange={onFooterChange}
      />,
    );

    // When
    await waitFor(() => {
      expect(onFooterChange).toHaveBeenCalled();
    });
    const footerConfig = onFooterChange.mock.calls.at(-1)?.[0];
    await act(async () => {
      footerConfig.onAction?.();
    });

    // Then
    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledTimes(1);
    });
    const toastPayload = toastMock.mock.calls[0]?.[0];
    expect(toastPayload.title).toBe("Scan Launched");
    expect(toastPayload.action).toBeDefined();
    expect(toastPayload.action.props.children.props.href).toBe("/scans");
  });

  it("uses a single manual scan when schedules are unavailable", async () => {
    // Given
    launchOrganizationScansMock.mockResolvedValue({ successCount: 1 });
    const onFooterChange = vi.fn();

    render(
      <OrgLaunchScan
        onClose={vi.fn()}
        onBack={vi.fn()}
        onFooterChange={onFooterChange}
        capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
      />,
    );

    // Then
    expect(
      screen.getByText(/scheduled scans are not available for trial accounts/i),
    ).toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();

    // When
    await waitFor(() => {
      expect(onFooterChange).toHaveBeenCalled();
    });
    const footerConfig = onFooterChange.mock.calls.at(-1)?.[0];
    await act(async () => {
      footerConfig.onAction?.();
    });

    // Then
    await waitFor(() => {
      expect(launchOrganizationScansMock).toHaveBeenCalledTimes(1);
    });
    expect(launchOrganizationScansMock).toHaveBeenCalledWith(
      ["provider-1"],
      "single",
    );
  });

  it("blocks manual scans when the trial scan limit is reached", async () => {
    // Given
    const onFooterChange = vi.fn();

    render(
      <OrgLaunchScan
        onClose={vi.fn()}
        onBack={vi.fn()}
        onFooterChange={onFooterChange}
        capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        isScanLimitReached
      />,
    );

    // When
    await waitFor(() => {
      expect(onFooterChange).toHaveBeenCalled();
    });
    const footerConfig = onFooterChange.mock.calls.at(-1)?.[0];
    await act(async () => {
      footerConfig.onAction?.();
    });

    // Then
    expect(screen.getByText(/reached your scan limit/i)).toBeInTheDocument();
    expect(footerConfig.actionDisabled).toBe(true);
    expect(launchOrganizationScansMock).not.toHaveBeenCalled();
  });
});
