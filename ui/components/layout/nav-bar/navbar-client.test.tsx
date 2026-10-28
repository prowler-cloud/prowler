import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { FeedsLoadingFallback, NavbarClient } from "./navbar-client";

vi.mock("next/navigation", () => ({
  usePathname: () => "/findings",
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/ThemeSwitch", () => ({
  ThemeSwitch: () => <button type="button">Theme switch</button>,
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  BreadcrumbNavigation: ({ title }: { title: string }) => (
    <nav aria-label="Breadcrumb">
      <h1>{title}</h1>
    </nav>
  ),
}));

vi.mock("@/components/layout/app-sidebar", () => ({
  MobileAppSidebar: () => <button type="button">Open menu</button>,
}));

vi.mock("../user-nav/user-nav", () => ({
  UserNav: () => <button type="button">User menu</button>,
}));

describe("NavbarClient", () => {
  beforeEach(() => {
    // The Lighthouse AI trigger is Cloud-only.
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
    });
  });

  it("shows the Lighthouse AI side-panel trigger in cloud", () => {
    // Given / When
    render(<NavbarClient title="Findings" />);

    // Then
    expect(screen.getByTestId("side-panel-ai-trigger")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Ask Lighthouse AI" }),
    ).toBeInTheDocument();
  });

  it("hides the Lighthouse AI trigger while the AI chat panel is already open", () => {
    // Given
    useSidePanelStore.setState({
      isOpen: true,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
    });

    // When
    render(<NavbarClient title="Findings" />);

    // Then
    expect(
      screen.queryByTestId("side-panel-ai-trigger"),
    ).not.toBeInTheDocument();
  });

  it("keeps the Lighthouse AI trigger while the panel shows a detail tab", () => {
    // Given: the panel is open but on the context (detail) tab, so the trigger
    // is still the way to switch to the AI chat.
    useSidePanelStore.setState({
      isOpen: true,
      selectedTab: SIDE_PANEL_TAB.CONTEXT,
    });

    // When
    render(<NavbarClient title="Findings" />);

    // Then
    expect(screen.getByTestId("side-panel-ai-trigger")).toBeInTheDocument();
  });

  it("hides the Lighthouse AI side-panel trigger in self-hosted (OSS) deployments", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    render(<NavbarClient title="Findings" />);

    // Then
    expect(
      screen.queryByTestId("side-panel-ai-trigger"),
    ).not.toBeInTheDocument();
  });

  it("draws a bottom separator that reaches the sidebar's edge", () => {
    // Given / When
    render(<NavbarClient title="Findings" />);

    // Then: same token as the sidebar's border-r, bled 16px left to meet it
    const header = screen.getByRole("banner");
    expect(header).toHaveClass(
      "border-b",
      "border-border-neutral-secondary",
      "-ml-4",
      "pl-4",
    );
    expect(header).not.toHaveClass("w-full");
  });

  it("keeps the feeds fallback on the shared ghost icon treatment", () => {
    // Given / When
    render(<FeedsLoadingFallback />);

    // Then: same 32px square as the rest of the navbar action cluster
    const button = screen.getByRole("button", { name: "Loading updates" });
    expect(button).toHaveClass("size-8");
    expect(button).not.toHaveClass("rounded-full");
  });
});
