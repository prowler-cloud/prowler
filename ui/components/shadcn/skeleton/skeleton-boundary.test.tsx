import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Skeleton } from "./skeleton";
import { SkeletonBoundary } from "./skeleton-boundary";

describe("SkeletonBoundary", () => {
  it("wraps resolved content with the shared skeleton reveal", () => {
    // Given
    render(
      <SkeletonBoundary fallback={<Skeleton aria-label="Loading content" />}>
        <section aria-label="Resolved content">Ready</section>
      </SkeletonBoundary>,
    );

    // When
    const reveal = screen.getByTestId("skeleton-content-reveal");

    // Then
    expect(screen.getByLabelText("Resolved content")).toBeInTheDocument();
    expect(reveal).toHaveAttribute("data-motion", "skeleton-content-handoff");
  });

  it("forwards className to the reveal wrapper", () => {
    // Given
    render(
      <SkeletonBoundary
        fallback={<Skeleton aria-label="Loading content" />}
        className="custom-boundary"
      >
        Ready
      </SkeletonBoundary>,
    );

    // When
    const reveal = screen.getByTestId("skeleton-content-reveal");

    // Then
    expect(reveal).toHaveClass("custom-boundary");
  });
});
