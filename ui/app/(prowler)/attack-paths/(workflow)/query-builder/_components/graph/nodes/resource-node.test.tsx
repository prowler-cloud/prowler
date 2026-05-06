import { render, screen } from "@testing-library/react";
import { type NodeProps, Position } from "@xyflow/react";
import { describe, expect, it, vi } from "vitest";

import type { GraphNode } from "@/types/attack-paths";

import { ResourceNode } from "./resource-node";

const hiddenHandlesMock = vi.hoisted(() => vi.fn(() => null));

vi.mock("./hidden-handles", () => ({
  HiddenHandles: hiddenHandlesMock,
}));

const buildGraphNode = (label: string, name: string): GraphNode => ({
  id: `${label}-${name}`,
  labels: [label],
  properties: { id: `${label}-${name}`, name },
});

const buildNodeProps = (graphNode: GraphNode): NodeProps =>
  ({
    id: graphNode.id,
    type: "resource",
    data: { graphNode },
    selected: false,
    dragging: false,
    zIndex: 0,
    isConnectable: false,
    positionAbsoluteX: 0,
    positionAbsoluteY: 0,
  }) as unknown as NodeProps;

describe("ResourceNode", () => {
  it("positions graph handles for horizontal left-to-right edges", () => {
    // Given
    const props = buildNodeProps(buildGraphNode("S3Bucket", "logs"));

    // When
    render(<ResourceNode {...props} />);

    // Then
    expect(hiddenHandlesMock).toHaveBeenCalledWith(
      expect.objectContaining({
        sourcePosition: Position.Right,
        sourceStyle: { left: 90, top: 26 },
        targetPosition: Position.Left,
        targetStyle: { left: 46, top: 26 },
      }),
      undefined,
    );
  });

  describe("node visual icons", () => {
    it("should render the S3 bucket icon with the resource label", () => {
      // Given
      const props = buildNodeProps(buildGraphNode("S3Bucket", "logs"));

      // When
      render(<ResourceNode {...props} />);

      // Then
      expect(
        screen.getByTestId("attack-path-node-icon-s3-bucket"),
      ).toHaveAccessibleName("S3 Bucket icon");
      expect(screen.getByText("logs")).toBeInTheDocument();
      expect(screen.getByText("S3 Bucket")).toBeInTheDocument();
    });

    it("should render a distinct VPC icon with the resource label", () => {
      // Given
      const props = buildNodeProps(buildGraphNode("VPC", "main-vpc"));

      // When
      render(<ResourceNode {...props} />);

      // Then
      expect(
        screen.getByTestId("attack-path-node-icon-vpc"),
      ).toHaveAccessibleName("VPC icon");
      expect(
        screen.queryByTestId("attack-path-node-icon-s3-bucket"),
      ).not.toBeInTheDocument();
      expect(screen.getByText("main-vpc")).toBeInTheDocument();
      expect(screen.getByText("VPC")).toBeInTheDocument();
    });
  });
});
