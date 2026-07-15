import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import { SUBMENU_KIND } from "@/types/components";

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
    const returnFocusElement = document.createElement("button");
    const onSelect = vi.fn(() => returnFocusElement);
    render(
      <SubmenuItem
        kind={SUBMENU_KIND.CLOUD_UPGRADE}
        label="Alerts"
        icon={TestIcon}
        cloudUpgradeFeature={CLOUD_UPGRADE_FEATURE.ALERTS}
        onSelect={onSelect}
      />,
    );

    // When
    const button = screen.getByRole("button", { name: /alerts/i });
    await user.click(button);

    // Then
    expect(button).not.toHaveAttribute("aria-disabled");
    expect(screen.getByText("Cloud")).toBeVisible();
    expect(
      screen.queryByRole("link", { name: /alerts/i }),
    ).not.toBeInTheDocument();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.ALERTS,
    );
    expect(onSelect).toHaveBeenCalledOnce();
    expect(useCloudUpgradeStore.getState().returnFocusElement).toBe(
      returnFocusElement,
    );
  });
});
