import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

    it("should show up to four readable lines for long resource names", () => {
      // Given
      const props = buildNodeProps(
        buildGraphNode("AWSRole", "AWSReservedSSO_AdministratorAccessExtra"),
      );

      // When
      const { container } = render(<ResourceNode {...props} />);

      // Then
      expect(screen.getByText("AWSReservedSSO_A")).toBeInTheDocument();
      expect(screen.getByText("dministratorAcce")).toBeInTheDocument();
      expect(screen.getByText("ssExtra")).toBeInTheDocument();
      expect(screen.getByText("AWS Role")).toBeInTheDocument();
      expect(container.querySelector("title")).toBeNull();
    });

    it("should expose the full resource name as an immediate tooltip when truncated", async () => {
      // Given
      const name =
        "arn:aws:iam::998057895221:role/OrganizationAccountAccessRole/integration";
      const props = buildNodeProps(buildGraphNode("AWSRole", name));

      // When
      render(<ResourceNode {...props} />);

      // Then
      expect(screen.getByText("arn:aws:iam::998")).toBeInTheDocument();
      expect(screen.getByText("057895221:role/O")).toBeInTheDocument();
      expect(screen.getByText("ntAccessRole/in…")).toBeInTheDocument();

      await userEvent.hover(
        screen.getByText("arn:aws:iam::998").closest("svg")!,
      );

      expect(await screen.findAllByText(name)).not.toHaveLength(0);
    });
  });
});
