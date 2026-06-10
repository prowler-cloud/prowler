import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SankeyChart } from "./sankey-chart";
import { getSankeyLayoutConfig } from "./sankey-chart.layout";

const mockPush = vi.fn();

vi.mock("@/lib", () => ({
  applyFailNonMutedFilters: (filters: unknown) => filters,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush }),
  useSearchParams: () => new URLSearchParams(),
}));

describe("SankeyChart", () => {
  it("uses layout-configured height for the empty-state container", () => {
    const data = {
      nodes: Array.from({ length: 14 }, (_, index) => ({
        name: `Node ${index}`,
      })),
      links: Array.from({ length: 12 }, (_, index) => ({
        source: index,
        target: 13,
        value: 0,
      })),
    };

    const baseHeight = 460;
    const layoutConfig = getSankeyLayoutConfig({
      baseHeight,
      nodes: data.nodes,
      links: data.links,
    });

    const { container } = render(
      <SankeyChart data={data} height={baseHeight} />,
    );

    expect(
      screen.getByText("No failed findings to display"),
    ).toBeInTheDocument();
    expect(container.firstElementChild).toHaveStyle({
      height: `${layoutConfig.height}px`,
    });
  });
});
