import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/shadcn/skeleton/skeleton", () => ({
  Skeleton: ({ className }: { className?: string }) => (
    <div data-testid="skeleton-block" data-class={className ?? ""} />
  ),
}));

import { ResourceDetailSkeleton } from "./resource-detail-skeleton";

describe("ResourceDetailSkeleton", () => {
  it("should render placeholders mirroring the resource info grid layout", () => {
    render(<ResourceDetailSkeleton />);

    // Account/Resource entity placeholders + 5 info fields (dates + service +
    // region) + actions button = at least 7 blocks rendered.
    const blocks = screen.getAllByTestId("skeleton-block");
    expect(blocks.length).toBeGreaterThanOrEqual(7);
  });
});
