import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";
import { usePageReadyStore } from "@/store/page-ready";

import { NavbarClient } from "./navbar-client";

const navigationMocks = vi.hoisted(() => ({
  pathname: "/findings",
  push: vi.fn(),
  searchParams: new URLSearchParams(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => navigationMocks.pathname,
  useRouter: () => ({ push: navigationMocks.push }),
  useSearchParams: () => navigationMocks.searchParams,
}));

vi.mock("@/hooks/use-sidebar", () => ({
  useSidebar: () => ({ isOpen: true, toggleOpen: vi.fn() }),
}));

vi.mock("@/components/ThemeSwitch", () => ({
  ThemeSwitch: () => <button type="button">Theme switch</button>,
}));

vi.mock("@/components/ui", () => ({
  BreadcrumbNavigation: ({
    title,
    titleAction,
  }: {
    title: string;
    titleAction?: ReactNode;
  }) => (
    <nav aria-label="Breadcrumb">
      <h1>{title}</h1>
      {titleAction}
    </nav>
  ),
}));

vi.mock("../sidebar/sheet-menu", () => ({
  SheetMenu: () => <button type="button">Open menu</button>,
}));

vi.mock("../sidebar/sidebar-toggle", () => ({
  SidebarToggle: () => <button type="button">Toggle sidebar</button>,
}));

vi.mock("../user-nav/user-nav", () => ({
  UserNav: () => <button type="button">User menu</button>,
}));

describe("NavbarClient", () => {
  beforeEach(() => {
    navigationMocks.pathname = "/findings";
    navigationMocks.push.mockClear();
    navigationMocks.searchParams = new URLSearchParams();
    window.localStorage.clear();
    // Default: the current route's content has loaded, so the icon is enabled.
    usePageReadyStore.setState({ readyPath: "/findings" });
  });

  it("renders an accessible contextual onboarding button in the breadcrumb", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <NavbarClient
        title="Findings"
        onboardingAction={{ flowId: "explore-findings" }}
      />,
    );

    // When
    await user.hover(
      screen.getByRole("button", {
        name: /start product tour: explore your findings/i,
      }),
    );

    // Then
    expect(
      screen.getByRole("heading", { name: "Findings" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("See how it works")).not.toHaveLength(0);
    expect(
      screen.getByRole("button", {
        name: /start product tour: explore your findings/i,
      }),
    ).toHaveClass("size-7");
  });

  it("pulses the onboarding icon while the tour has not been seen", () => {
    render(
      <NavbarClient
        title="Findings"
        onboardingAction={{ flowId: "explore-findings" }}
      />,
    );

    const icon = screen
      .getByRole("button", {
        name: /start product tour: explore your findings/i,
      })
      .querySelector("svg");
    expect(icon).toHaveClass("animate-pulse");
  });

  it("keeps the onboarding button but stops pulsing once the tour is closed", () => {
    const flow = getFlowById("explore-findings");
    localStorageAdapter.set(flow!.tour, {
      tourId: flow!.tour.id,
      version: flow!.tour.version,
      state: "dismissed",
      completedAt: "2026-01-01T00:00:00.000Z",
    });

    render(
      <NavbarClient
        title="Findings"
        onboardingAction={{ flowId: "explore-findings" }}
      />,
    );

    const button = screen.getByRole("button", {
      name: /start product tour: explore your findings/i,
    });
    expect(button).toBeInTheDocument();
    expect(button.querySelector("svg")).not.toHaveClass("animate-pulse");
  });

  it("navigates to the current flow replay URL while preserving current-route params", async () => {
    // Given
    navigationMocks.pathname = "/compliance";
    navigationMocks.searchParams = new URLSearchParams("scanId=scan-1&foo=bar");
    usePageReadyStore.setState({ readyPath: "/compliance" });
    const user = userEvent.setup();
    render(
      <NavbarClient
        title="Compliance"
        onboardingAction={{ flowId: "view-compliance" }}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", {
        name: /start product tour: check compliance/i,
      }),
    );

    // Then
    expect(navigationMocks.push).toHaveBeenCalledWith(
      "/compliance?scanId=scan-1&foo=bar&onboarding=view-compliance",
    );
  });

  it("navigates to the fallback flow without leaking current-route params", async () => {
    // Given
    navigationMocks.pathname = "/findings";
    navigationMocks.searchParams = new URLSearchParams(
      "filter%5Bseverity__in%5D=critical",
    );
    const user = userEvent.setup();
    render(
      <NavbarClient
        title="Findings"
        onboardingAction={{
          flowId: "explore-findings",
          fallbackFlowId: "view-first-scan",
          useFallback: true,
        }}
      />,
    );

    // When
    await user.click(
      screen.getByRole("button", {
        name: /start product tour: run your first scan/i,
      }),
    );

    // Then
    expect(navigationMocks.push).toHaveBeenCalledWith(
      "/scans?onboarding=view-first-scan",
    );
  });

  it("hides the replay icon until the route's content has loaded", () => {
    // Given the page has not signalled ready for the current route
    usePageReadyStore.setState({ readyPath: null });

    // When
    render(
      <NavbarClient
        title="Findings"
        onboardingAction={{ flowId: "explore-findings" }}
      />,
    );

    // Then the icon is not rendered at all
    expect(
      screen.queryByRole("button", {
        name: /start product tour: explore your findings/i,
      }),
    ).not.toBeInTheDocument();
  });

  it("does not render a contextual onboarding button for unknown flows", () => {
    // Given / When
    render(
      <NavbarClient
        title="Findings"
        onboardingAction={{ flowId: "unknown-flow" }}
      />,
    );

    // Then
    expect(
      screen.queryByRole("button", { name: /start product tour/i }),
    ).not.toBeInTheDocument();
  });
});
