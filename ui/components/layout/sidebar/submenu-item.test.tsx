import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/lib/cloud-upgrade";
import { useCloudUpgradeStore } from "@/store";

import { SubmenuItem } from "./submenu-item";

vi.mock("next/navigation", () => ({
  usePathname: () => "/",
}));

const TestIcon = ({ size = 16 }: { size?: number }) => (
  <svg aria-hidden="true" height={size} width={size} />
);

describe("SubmenuItem", () => {
  afterEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("should open the Alerts upgrade modal from a Local Server menu item", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <SubmenuItem
        href="/alerts"
        label="Alerts"
        icon={TestIcon}
        cloudOnly
        cloudUpgradeFeature={CLOUD_UPGRADE_FEATURE.ALERTS}
      />,
    );

    // When
    const button = screen.getByRole("button", { name: /alerts/i });
    await user.click(button);

    // Then
    expect(button).not.toHaveAttribute("aria-disabled");
    expect(screen.getByText("Cloud")).toHaveClass("h-5", "text-[10px]");
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.ALERTS,
    );
  });

  it("should open the scan configuration upgrade without rendering a link", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <SubmenuItem
        href="/scans/config"
        label="Scan"
        icon={TestIcon}
        cloudOnly
        cloudUpgradeFeature={CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION}
      />,
    );

    // When
    const button = screen.getByRole("button", { name: /scan/i });
    await user.click(button);

    // Then
    expect(
      screen.queryByRole("link", { name: /scan/i }),
    ).not.toBeInTheDocument();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION,
    );
  });
});
