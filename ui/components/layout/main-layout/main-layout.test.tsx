import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import MainLayout from "./main-layout";

vi.mock("@/hooks/use-sidebar", () => ({
  useSidebar: vi.fn(),
}));

vi.mock("@/hooks/use-store", () => ({
  useStore: () => ({
    getOpenState: () => true,
    settings: { disabled: false },
  }),
}));

vi.mock("../sidebar/sidebar", () => ({
  Sidebar: () => <aside data-testid="sidebar" />,
}));

vi.mock("@/components/shared/cloud-upgrade-modal", () => ({
  CloudUpgradeModal: () => <div data-testid="cloud-upgrade-modal" />,
}));

describe("MainLayout", () => {
  it("mounts the shared Cloud upgrade modal with page content", () => {
    render(
      <MainLayout>
        <div>Page content</div>
      </MainLayout>,
    );

    expect(screen.getByTestId("cloud-upgrade-modal")).toBeInTheDocument();
    expect(screen.getByText("Page content")).toBeVisible();
  });
});
