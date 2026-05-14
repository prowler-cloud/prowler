import { act, render, waitFor } from "@testing-library/react";
import type { ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useOrgSetupStore } from "@/store/organizations/store";

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
});
