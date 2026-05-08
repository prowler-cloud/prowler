import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { AttackPathGraphData } from "@/types/attack-paths";

import { GraphLegend } from "./graph-legend";

vi.mock("next-themes", () => ({
  useTheme: () => ({ resolvedTheme: "dark" }),
}));

const graphData: AttackPathGraphData = {
  nodes: [
    {
      id: "aws-account",
      labels: ["AWSAccount"],
      properties: { name: "Production" },
    },
    { id: "bucket", labels: ["S3Bucket"], properties: { name: "logs" } },
    { id: "vpc", labels: ["VPC"], properties: { name: "main" } },
    {
      id: "finding",
      labels: ["ProwlerFinding"],
      properties: { check_title: "Public bucket", severity: "critical" },
    },
  ],
};

describe("GraphLegend", () => {
  it("should explain graph visuals by semantic groups instead of repeating node labels", () => {
    // Given - A graph with provider, resource, and finding nodes

    // When
    render(<GraphLegend data={graphData} />);

    // Then
    expect(
      screen.getByRole("heading", { name: /provider roots/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /resource categories/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /findings by risk/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /states/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /edges/i })).toBeInTheDocument();

    expect(screen.getByText("Provider / account root")).toBeInTheDocument();
    expect(screen.getByText("Storage")).toBeInTheDocument();
    expect(screen.getByText("Network")).toBeInTheDocument();
    expect(screen.getByText("Compute")).toBeInTheDocument();
    expect(screen.getByText("Identity")).toBeInTheDocument();
    expect(screen.getByText("Secret / misc")).toBeInTheDocument();

    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Medium")).toBeInTheDocument();
    expect(screen.getByText("Low / Info")).toBeInTheDocument();

    expect(screen.getByText("Selected node")).toBeInTheDocument();
    expect(screen.getByText("Node with findings")).toBeInTheDocument();
    expect(screen.getByText("Normal edge")).toBeInTheDocument();
    expect(screen.getByText("Finding edge")).toBeInTheDocument();
    expect(screen.getByText("Highlighted path")).toBeInTheDocument();

    expect(screen.queryByText("S3 Bucket")).not.toBeInTheDocument();
    expect(screen.queryByText("VPC")).not.toBeInTheDocument();
    expect(screen.queryByText(/ctrl/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/scroll to zoom/i)).not.toBeInTheDocument();
  });

  it("should stay hidden until graph nodes are available", () => {
    // Given - No graph nodes have been loaded yet
    const emptyGraphData: AttackPathGraphData = { nodes: [] };

    // When
    const { container } = render(<GraphLegend data={emptyGraphData} />);

    // Then
    expect(container).toBeEmptyDOMElement();
    expect(
      screen.queryByRole("heading", { name: /provider roots/i }),
    ).not.toBeInTheDocument();
  });
});
