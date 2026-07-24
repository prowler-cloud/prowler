import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import MainLayout from "./main-layout";

vi.mock("@/components/layout/app-sidebar", () => ({
  AppSidebar: () => <aside data-testid="sidebar" />,
}));

vi.mock("@/components/shared/cloud-upgrade-modal", () => ({
  CloudUpgradeModal: () => <div data-testid="cloud-upgrade-modal" />,
}));

vi.mock("@/components/findings/jira-dispatch-modal-host", () => ({
  JiraDispatchModalHost: () => <div data-testid="jira-dispatch-modal-host" />,
}));

describe("MainLayout", () => {
  it("mounts the shared Cloud upgrade modal with page content", () => {
    render(
      <MainLayout>
        <div>Page content</div>
      </MainLayout>,
    );

    expect(screen.getByTestId("cloud-upgrade-modal")).toBeInTheDocument();
    expect(screen.getByTestId("jira-dispatch-modal-host")).toBeInTheDocument();
    expect(screen.getByTestId("sidebar")).toBeInTheDocument();
    expect(screen.getByText("Page content")).toBeVisible();
    expect(screen.getByRole("main")).toBeVisible();
  });

  it("keeps the desktop sidebar offset based on the viewport", () => {
    // Given / When
    render(
      <MainLayout>
        <div>Page content</div>
      </MainLayout>,
    );

    // Then: a right panel may narrow main, but the desktop sidebar stays open.
    // Margin reaches the sidebar edge; the 16px gutter is padding so the
    // navbar's bled border-b paints instead of being clipped by the scroller.
    expect(screen.getByText("Page content").parentElement).toHaveClass(
      "min-[64rem]:ml-[264px]",
      "pl-4",
    );
  });

  it("marks main as the responsive container for pushed page content", () => {
    // Given / When
    render(
      <MainLayout>
        <div>Page content</div>
      </MainLayout>,
    );

    // Then
    expect(screen.getByText("Page content").parentElement).toHaveAttribute(
      "data-responsive-container",
    );
  });
});
