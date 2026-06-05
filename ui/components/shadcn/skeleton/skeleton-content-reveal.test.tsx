import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SkeletonContentReveal } from "./skeleton-content-reveal";

describe("SkeletonContentReveal", () => {
  it("reveals streamed content with insertion-time CSS motion", () => {
    // Given
    render(
      <SkeletonContentReveal>
        <section aria-label="Loaded content">Ready</section>
      </SkeletonContentReveal>,
    );

    // When
    const wrapper = screen.getByTestId("skeleton-content-reveal");

    // Then
    expect(screen.getByLabelText("Loaded content")).toBeInTheDocument();
    expect(wrapper).toHaveAttribute("data-motion", "skeleton-content-handoff");
    expect(wrapper).toHaveClass(
      "transition-[opacity,transform]",
      "duration-700",
      "starting:opacity-0",
      "starting:translate-y-3",
      "opacity-100",
      "translate-y-0",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });

  it("merges caller classes without dropping the motion contract", () => {
    // Given
    render(
      <SkeletonContentReveal className="custom-reveal">
        Ready
      </SkeletonContentReveal>,
    );

    // When
    const wrapper = screen.getByTestId("skeleton-content-reveal");

    // Then
    expect(wrapper).toHaveClass(
      "custom-reveal",
      "transition-[opacity,transform]",
      "starting:opacity-0",
    );
  });
});
