import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/shadcn/skeleton/skeleton", () => ({
  Skeleton: ({ className }: { className?: string }) => (
    <div data-testid="skeleton-block" data-class={className ?? ""} />
  ),
}));

import { ResourceDetailSkeleton } from "./resource-detail-skeleton";

describe("ResourceDetailSkeleton", () => {
  it("should include placeholders for group and resource type fields", () => {
    render(<ResourceDetailSkeleton />);

    const blocks = screen.getAllByTestId("skeleton-block");
    const classes = blocks.map(
      (block) => block.getAttribute("data-class") ?? "",
    );

    expect(classes).toContain("h-3.5 w-10 rounded");
    expect(classes).toContain("h-5 w-18 rounded");
    expect(classes).toContain("h-3.5 w-20 rounded");
    expect(classes).toContain("h-5 w-28 rounded");
  });
});
