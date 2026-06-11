import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Skeleton } from "./skeleton";

describe("Skeleton", () => {
  it("uses a subtle scanner animation that respects reduced motion", () => {
    // Given
    render(<Skeleton aria-label="Loading providers" />);

    // When
    const skeleton = screen.getByLabelText("Loading providers");

    // Then
    expect(skeleton).toHaveClass(
      "relative",
      "overflow-hidden",
      "bg-border-neutral-tertiary",
      "transition-colors",
      "duration-500",
      "ease-out",
    );

    const scanner = skeleton.querySelector("[data-slot='skeleton-scanner']");
    expect(scanner).toHaveClass(
      "animate-skeleton-scan",
      "bg-gradient-to-r",
      "from-transparent",
      "via-white/10",
      "to-transparent",
      "motion-reduce:hidden",
    );
  });
});
