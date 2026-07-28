import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { AppSidebarContent } from "./app-sidebar-content";
import { useAppSidebarMode } from "./app-sidebar-mode-store";
import { APP_SIDEBAR_MODE } from "./types";

const {
  openCloudUpgradeMock,
  openLaunchScanModalMock,
  pathnameValue,
  pushMock,
} = vi.hoisted(() => ({
  openCloudUpgradeMock: vi.fn(),
  openLaunchScanModalMock: vi.fn(),
  pathnameValue: { current: "/findings" },
  pushMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => pathnameValue.current,
  useRouter: () => ({ push: pushMock }),
}));

vi.mock("@/hooks", () => ({
  useAuth: () => ({ permissions: {} }),
}));

vi.mock("@/hooks/use-runtime-config", () => ({
  useRuntimeConfig: () => ({ apiDocsUrl: "https://local.example/docs" }),
}));

vi.mock("@/store", () => ({
  useScansStore: (
    selector: (state: {
      openLaunchScanModal: typeof openLaunchScanModalMock;
    }) => unknown,
  ) => selector({ openLaunchScanModal: openLaunchScanModalMock }),
  useCloudUpgradeStore: (
    selector: (state: {
      openCloudUpgrade: typeof openCloudUpgradeMock;
    }) => unknown,
  ) => selector({ openCloudUpgrade: openCloudUpgradeMock }),
}));

vi.mock("@/app/(prowler)/lighthouse/_components/navigation", () => ({
  LighthouseV2SidebarChat: () => <div data-testid="lighthouse-chat-sidebar" />,
}));

describe("AppSidebarContent", () => {
  beforeEach(() => {
    pathnameValue.current = "/findings";
    pushMock.mockClear();
    openCloudUpgradeMock.mockClear();
    openLaunchScanModalMock.mockClear();
    useAppSidebarMode.setState({ mode: APP_SIDEBAR_MODE.BROWSE });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("shares the brand, Launch Scan action and Local Server Cloud affordances", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    vi.stubEnv("NEXT_PUBLIC_PROWLER_RELEASE_VERSION", "5.8.0");
    const user = userEvent.setup();

    // When
    render(<AppSidebarContent />);

    // Then
    const homeLink = screen.getByRole("link", { name: "Prowler home" });
    expect(homeLink).toBeVisible();
    expect(screen.getByRole("link", { name: "Launch Scan" })).toHaveAttribute(
      "href",
      "/scans?launchScan=true",
    );
    expect(screen.getByText("5.8.0")).toBeVisible();

    await user.click(screen.getByRole("button", { name: "Chat" }));
    expect(openCloudUpgradeMock).toHaveBeenCalledWith(
      CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI,
      undefined,
    );
    expect(screen.getAllByText("Cloud").length).toBeGreaterThan(0);
  });

  it("keeps the existing Lighthouse chat sidebar in Cloud Chat mode", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    useAppSidebarMode.setState({ mode: APP_SIDEBAR_MODE.CHAT });

    // When
    render(<AppSidebarContent />);

    // Then
    expect(screen.getByTestId("lighthouse-chat-sidebar")).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Service status" }),
    ).toHaveAttribute("href", "https://status.prowler.com");
    expect(
      screen.queryByText("All systems operational"),
    ).not.toBeInTheDocument();
  });

  it("opens the current scan modal instead of navigating from the scans route", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    pathnameValue.current = "/scans";
    const user = userEvent.setup();

    // When
    render(<AppSidebarContent />);
    await user.click(screen.getByRole("button", { name: "Launch Scan" }));

    // Then
    expect(openLaunchScanModalMock).toHaveBeenCalledOnce();
    expect(
      screen.queryByRole("link", { name: "Launch Scan" }),
    ).not.toBeInTheDocument();
  });
});
