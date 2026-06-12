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
  relationships: [
    { id: "r1", source: "aws-account", target: "bucket", label: "HAS" },
    { id: "r2", source: "bucket", target: "vpc", label: "CAN_ACCESS" },
    { id: "r3", source: "bucket", target: "finding", label: "HAS_FINDING" },
  ],
};

describe("GraphLegend", () => {
  it("should explain concrete visible node types without generic categories", () => {
    // Given - A graph with provider, resource, and finding nodes

    // When
    render(
      <GraphLegend data={graphData} expandedResources={new Set(["bucket"])} />,
    );

    // Then
    expect(
      screen.getByRole("heading", { name: /provider roots/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /node types/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /findings by risk/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /states/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /edges/i })).toBeInTheDocument();

    expect(screen.getByText("Provider")).toBeInTheDocument();
    expect(screen.getByText("S3 Bucket")).toBeInTheDocument();
    expect(screen.getByText("VPC")).toBeInTheDocument();
    expect(screen.queryByText("Storage")).not.toBeInTheDocument();
    expect(screen.queryByText("Network")).not.toBeInTheDocument();
    expect(screen.queryByText("Compute")).not.toBeInTheDocument();
    expect(screen.queryByText("Identity")).not.toBeInTheDocument();
    expect(screen.queryByText("Secret / misc")).not.toBeInTheDocument();

    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.queryByText("High")).not.toBeInTheDocument();
    expect(screen.queryByText("Medium")).not.toBeInTheDocument();
    expect(screen.queryByText("Low / Info")).not.toBeInTheDocument();

    expect(screen.getByText("Selected node")).toBeInTheDocument();
    expect(screen.getByText("Node with findings")).toBeInTheDocument();
    expect(screen.getByText("Normal edge")).toBeInTheDocument();
    expect(screen.getByText("Finding edge")).toBeInTheDocument();
    expect(screen.getByText("Highlighted path")).toBeInTheDocument();
    expect(
      screen.getByRole("img", {
        name: /highlighted path: prowler green path/i,
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/orange path/i)).not.toBeInTheDocument();

    expect(screen.queryByText(/ctrl/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/scroll to zoom/i)).not.toBeInTheDocument();
  });

  it("should hide finding legend items when finding nodes are hidden", () => {
    // Given - A resource has related findings, but it is not expanded yet

    // When
    render(<GraphLegend data={graphData} />);

    // Then
    expect(
      screen.queryByRole("heading", { name: /findings by risk/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Finding edge")).not.toBeInTheDocument();
    expect(screen.getByText("Node with findings")).toBeInTheDocument();
  });

  it("should keep unattached findings visible in the legend", () => {
    // Given - Findings have no connected resource and stay visible in the full graph
    const findingsOnlyGraphData: AttackPathGraphData = {
      nodes: [
        {
          id: "finding-critical",
          labels: ["ProwlerFinding"],
          properties: { check_title: "Critical finding", severity: "critical" },
        },
        {
          id: "finding-high",
          labels: ["ProwlerFinding"],
          properties: { check_title: "High finding", severity: "high" },
        },
      ],
      relationships: [],
    };

    // When
    render(<GraphLegend data={findingsOnlyGraphData} />);

    // Then
    expect(
      screen.getByRole("heading", { name: /findings by risk/i }),
    ).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("should list policy and role node types separately", () => {
    // Given - A graph whose visible nodes are all identity-related, but distinct
    const identityGraphData: AttackPathGraphData = {
      nodes: [
        {
          id: "aws-account",
          labels: ["AWSAccount"],
          properties: { name: "Production" },
        },
        {
          id: "role",
          labels: ["PermissionRole"],
          properties: { name: "prowler-pro-dev-gha-role" },
        },
        {
          id: "policy",
          labels: ["AWSPolicy"],
          properties: { name: "IAMPermissions" },
        },
        {
          id: "statement",
          labels: ["AWSPolicyStatement"],
          properties: { name: "policy statement" },
        },
      ],
      relationships: [
        { id: "r1", source: "aws-account", target: "role", label: "HAS" },
        { id: "r2", source: "role", target: "policy", label: "HAS" },
        { id: "r3", source: "policy", target: "statement", label: "HAS" },
      ],
    };

    // When
    render(<GraphLegend data={identityGraphData} />);

    // Then
    expect(screen.getByText("Permission Role")).toBeInTheDocument();
    expect(screen.getByText("AWS Policy")).toBeInTheDocument();
    expect(screen.getByText("AWS Policy Statement")).toBeInTheDocument();
    expect(screen.queryByText("Identity")).not.toBeInTheDocument();
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
