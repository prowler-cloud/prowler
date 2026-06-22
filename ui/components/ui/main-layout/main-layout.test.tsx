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

describe("MainLayout", () => {
  it("renders subdued background glows for side-nav contrast", () => {
    render(
      <MainLayout>
        <div>Page content</div>
      </MainLayout>,
    );

    const topGlow =
      screen.getByTestId("sidebar").previousElementSibling
        ?.previousElementSibling;
    const bottomGlow = screen.getByTestId("sidebar").previousElementSibling;

    expect(topGlow).toHaveClass("h-[120%]", "w-[160%]", "opacity-[7%]");
    expect(bottomGlow).toHaveClass("h-[50%]", "w-[50%]", "opacity-[7%]");
  });
});
