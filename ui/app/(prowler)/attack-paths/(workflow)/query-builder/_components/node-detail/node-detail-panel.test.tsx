import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import type { GraphNode } from "@/types/attack-paths";

import { NodeDetailPanel } from "./node-detail-panel";

vi.mock("@/components/ui/sheet/sheet", () => ({
  Sheet: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  SheetContent: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  SheetDescription: ({ children }: { children: ReactNode }) => (
    <div>{children}</div>
  ),
  SheetHeader: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  SheetTitle: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

vi.mock("./node-overview", () => ({
  NodeOverview: () => <div>Node overview</div>,
}));

vi.mock("./node-findings", () => ({
  NodeFindings: () => <div>Node findings</div>,
}));

vi.mock("./node-resources", () => ({
  NodeResources: () => <div>Node resources</div>,
}));

const findingNode: GraphNode = {
  id: "graph-node-id",
  labels: ["ProwlerFinding"],
  properties: {
    id: "finding-123",
    check_title: "Open S3 bucket",
    name: "Open S3 bucket",
  },
};

const resourceNode: GraphNode = {
  id: "resource-node-id",
  labels: ["S3Bucket"],
  properties: {
    id: "bucket-123",
    name: "bucket-123",
  },
};

describe("NodeDetailPanel", () => {
  it("renders the view finding button only for finding nodes", () => {
    const { rerender } = render(<NodeDetailPanel node={findingNode} />);

    expect(
      screen.getByRole("button", { name: /view finding finding-123/i }),
    ).toBeInTheDocument();

    rerender(<NodeDetailPanel node={resourceNode} />);

    expect(
      screen.queryByRole("button", { name: /view finding/i }),
    ).not.toBeInTheDocument();
  });

  it("calls onViewFinding with the node finding id", async () => {
    const user = userEvent.setup();
    const onViewFinding = vi.fn();

    render(
      <NodeDetailPanel node={findingNode} onViewFinding={onViewFinding} />,
    );

    await user.click(
      screen.getByRole("button", { name: /view finding finding-123/i }),
    );

    expect(onViewFinding).toHaveBeenCalledWith("finding-123");
  });

  it("disables the button and shows the spinner while loading", () => {
    render(<NodeDetailPanel node={findingNode} viewFindingLoading />);

    const button = screen.getByRole("button", {
      name: /view finding finding-123/i,
    });

    expect(button).toBeDisabled();
    expect(screen.getByLabelText("Loading")).toHaveClass("size-4");
  });
});
