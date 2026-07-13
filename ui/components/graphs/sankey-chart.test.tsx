import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CustomNode, SankeyChart } from "./sankey-chart";
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

  it("renders risk and severity node labels with middle-aligned text", () => {
    const x = 10;
    const y = 20;
    const width = 70;
    const height = 80;
    const nodeCenterY = y + height / 2;

    render(
      <svg>
        <CustomNode
          x={x}
          y={y}
          width={width}
          height={height}
          payload={{ name: "High", value: 9, newFindings: 3, change: 1 }}
          containerWidth={200}
          colors={{ High: "#ff0000" }}
        />
      </svg>,
    );

    const textElements = screen.getAllByText(/High|9/);
    const nameLabel = textElements.find(
      (element) => element.textContent === "High",
    );
    const valueLabel = textElements.find(
      (element) => element.textContent === "9",
    );

    expect(nameLabel).toBeDefined();
    expect(valueLabel).toBeDefined();

    if (!nameLabel || !valueLabel) {
      throw new Error(
        "Expected both node name and value labels to be rendered.",
      );
    }

    expect(nameLabel).toHaveAttribute("dominant-baseline", "middle");
    expect(valueLabel).toHaveAttribute("dominant-baseline", "middle");

    const nameY = Number.parseFloat(nameLabel.getAttribute("y") || "0");
    const valueY = Number.parseFloat(valueLabel.getAttribute("y") || "0");

    expect(nameY).toBeLessThan(nodeCenterY);
    expect(valueY).toBeGreaterThan(nodeCenterY);
    expect((nameY + valueY) / 2).toBeCloseTo(nodeCenterY);
  });
});
