import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type NodeProps, Position } from "@xyflow/react";
import { describe, expect, it, vi } from "vitest";

import type { GraphNode } from "@/types/attack-paths";

import { FindingNode } from "./finding-node";

const hiddenHandlesMock = vi.hoisted(() => vi.fn(() => null));

vi.mock("./hidden-handles", () => ({
  HiddenHandles: hiddenHandlesMock,
}));

const buildFindingNode = (severity: string, title: string): GraphNode => ({
  id: `${severity}-finding`,
  labels: ["ProwlerFinding"],
  properties: { check_title: title, id: `${severity}-finding`, severity },
});

const buildNodeProps = (graphNode: GraphNode): NodeProps =>
  ({
    id: graphNode.id,
    type: "finding",
    data: { graphNode },
    selected: false,
    dragging: false,
    zIndex: 0,
    isConnectable: false,
    positionAbsoluteX: 0,
    positionAbsoluteY: 0,
  }) as unknown as NodeProps;

describe("FindingNode", () => {
  it("positions graph handles for horizontal left-to-right edges", () => {
    // Given
    const props = buildNodeProps(
      buildFindingNode("critical", "Root key exposed"),
    );

    // When
    render(<FindingNode {...props} />);

    // Then
    expect(hiddenHandlesMock).toHaveBeenCalledWith(
      expect.objectContaining({
        sourcePosition: Position.Right,
        sourceStyle: { left: 97, top: 26 },
        targetPosition: Position.Left,
        targetStyle: { left: 53, top: 26 },
      }),
      undefined,
    );
  });

  describe("severity visuals", () => {
    it("should render the critical finding risk icon with readable text", () => {
      // Given
      const props = buildNodeProps(
        buildFindingNode("critical", "Root key exposed"),
      );

      // When
      render(<FindingNode {...props} />);

      // Then
      expect(
        screen.getByTestId("attack-path-finding-icon-critical"),
      ).toHaveAccessibleName("Critical finding risk icon");
      expect(screen.getByText("Root key exposed")).toBeInTheDocument();
      expect(screen.getByText("critical")).toBeInTheDocument();
    });

    it("should render a distinct medium finding risk icon with readable text", () => {
      // Given
      const props = buildNodeProps(
        buildFindingNode("medium", "Bucket lacks logging"),
      );

      // When
      render(<FindingNode {...props} />);

      // Then
      expect(
        screen.getByTestId("attack-path-finding-icon-medium"),
      ).toHaveAccessibleName("Medium finding risk icon");
      expect(
        screen.queryByTestId("attack-path-finding-icon-critical"),
      ).not.toBeInTheDocument();
      expect(screen.getByText("Bucket lacks")).toBeInTheDocument();
      expect(screen.getByText("logging")).toBeInTheDocument();
      expect(screen.getByText("medium")).toBeInTheDocument();
    });

    it("should expose the full finding title as an immediate tooltip when truncated", async () => {
      // Given
      const title =
        "Ensure administrator access policies are rotated regularly";
      const props = buildNodeProps(buildFindingNode("high", title));

      // When
      render(<FindingNode {...props} />);

      // Then
      expect(screen.getByText("Ensure")).toBeInTheDocument();
      expect(screen.getByText("administrator")).toBeInTheDocument();
      expect(screen.getByText("access policies")).toBeInTheDocument();
      expect(screen.getByText("are rotated…")).toBeInTheDocument();
      expect(screen.getByText("high")).toBeInTheDocument();

      await userEvent.hover(screen.getByText("Ensure").closest("svg")!);

      expect(await screen.findAllByText(title)).not.toHaveLength(0);
    });
  });
});
