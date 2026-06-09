import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Menu } from "./menu";

const { openLaunchScanModalMock, pathnameValue } = vi.hoisted(() => ({
  openLaunchScanModalMock: vi.fn(),
  pathnameValue: { current: "/findings" },
}));

vi.mock("next/navigation", () => ({
  usePathname: () => pathnameValue.current,
}));

vi.mock("@/hooks", () => ({
  useAuth: () => ({
    permissions: {},
  }),
}));

vi.mock("@/lib/menu-list", () => ({
  getMenuList: () => [],
}));

vi.mock("@/store", () => ({
  useScansStore: (
    selector: (state: { openLaunchScanModal: () => void }) => unknown,
  ) => selector({ openLaunchScanModal: openLaunchScanModalMock }),
}));

describe("Menu", () => {
  it("links scan to the scans page with the modal open", () => {
    pathnameValue.current = "/findings";

    render(<Menu isOpen />);

    const launchScanLink = screen.getByRole("link", { name: /launch scan/i });
    const launchScanWrapper = launchScanLink.closest("div.flex.shrink-0");

    expect(launchScanLink).toHaveAttribute("href", "/scans?launchScan=true");
    expect(launchScanWrapper).toHaveClass("flex", "justify-center");
    expect(launchScanLink).toHaveClass("h-14", "w-[180px]", "p-1");
    expect(launchScanLink).not.toHaveClass("h-8", "h-9", "h-10");
    expect(screen.getByText("Scan")).toHaveClass("text-xl", "leading-8");
    expect(screen.getByText("Scan")).not.toHaveClass("text-2xl", "font-bold");
    expect(
      launchScanLink.querySelector('svg[viewBox="0 0 432.08 396.77"]'),
    ).toBeInTheDocument();
  });

  it("opens the launch scan modal without navigation when already on scans", async () => {
    pathnameValue.current = "/scans";

    render(<Menu isOpen />);

    await screen.getByRole("button", { name: /launch scan/i }).click();

    expect(openLaunchScanModalMock).toHaveBeenCalledTimes(1);
    expect(
      screen.queryByRole("link", { name: /launch scan/i }),
    ).not.toBeInTheDocument();
  });

  it("shows the Prowler icon when the menu is collapsed", () => {
    pathnameValue.current = "/findings";

    render(<Menu isOpen={false} />);

    const launchScanLink = screen.getByRole("link", { name: /launch scan/i });

    expect(launchScanLink).toHaveClass("h-9", "w-14");
    expect(launchScanLink).not.toHaveClass("h-14");
    expect(
      launchScanLink.querySelector('svg[viewBox="0 0 432.08 396.77"]'),
    ).toBeInTheDocument();
  });
});
