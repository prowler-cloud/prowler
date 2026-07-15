import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FileText, Settings, ShieldCheck } from "lucide-react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { SidebarNavigation } from "./sidebar-navigation";
import { NAVIGATION_ITEM_KIND, type NavigationSection } from "./types";

const { openCloudUpgradeMock } = vi.hoisted(() => ({
  openCloudUpgradeMock: vi.fn(),
}));

vi.mock("@/store", () => ({
  useCloudUpgradeStore: (
    selector: (state: {
      openCloudUpgrade: typeof openCloudUpgradeMock;
    }) => unknown,
  ) => selector({ openCloudUpgrade: openCloudUpgradeMock }),
}));

const sections: NavigationSection[] = [
  {
    label: "SECURITY",
    items: [
      {
        kind: NAVIGATION_ITEM_KIND.LINK,
        href: "/compliance",
        label: "Compliance",
        icon: ShieldCheck,
        active: true,
      },
    ],
  },
  {
    label: "SETTINGS",
    items: [
      {
        kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
        label: "Configuration",
        icon: Settings,
        defaultOpen: false,
        children: [
          {
            kind: NAVIGATION_ITEM_KIND.LINK,
            href: "/providers",
            label: "Providers",
            active: true,
          },
          {
            kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
            label: "Alerts",
            cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.ALERTS,
          },
        ],
      },
    ],
  },
  {
    label: "HELP",
    items: [
      {
        kind: NAVIGATION_ITEM_KIND.LINK,
        href: "https://docs.prowler.com/",
        label: "Documentation",
        icon: FileText,
        target: "_blank",
      },
    ],
  },
];

describe("SidebarNavigation", () => {
  beforeEach(() => {
    openCloudUpgradeMock.mockClear();
  });

  it("renders grouped semantic navigation with accessible active destinations", () => {
    // Given / When
    render(<SidebarNavigation sections={sections} />);

    // Then
    expect(
      screen.getByRole("navigation", { name: "Main navigation" }),
    ).toBeVisible();
    expect(screen.getByText("SECURITY")).toBeVisible();
    expect(screen.getByRole("link", { name: "Compliance" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByRole("link", { name: "Providers" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    const activeParent = screen.getByRole("button", {
      name: "Configuration",
    });
    expect(activeParent).toHaveAttribute("aria-expanded", "true");
    expect(activeParent).toHaveClass(
      "border-border-sidebar-active",
      "bg-bg-sidebar-active",
    );
  });

  it("marks external links and opens contextual Cloud upgrades", async () => {
    // Given
    const user = userEvent.setup();
    const returnFocusElement = document.createElement("button");
    const onSelect = vi.fn(() => returnFocusElement);
    render(<SidebarNavigation sections={sections} onSelect={onSelect} />);

    // When
    await user.click(screen.getByRole("button", { name: /alerts/i }));

    // Then
    expect(openCloudUpgradeMock).toHaveBeenCalledWith(
      CLOUD_UPGRADE_FEATURE.ALERTS,
      returnFocusElement,
    );
    expect(screen.getByText("Cloud")).toBeVisible();
    expect(screen.getByRole("link", { name: "Documentation" })).toHaveAttribute(
      "target",
      "_blank",
    );
    expect(screen.getByRole("link", { name: "Documentation" })).toHaveAttribute(
      "rel",
      "noopener noreferrer",
    );
  });
});
