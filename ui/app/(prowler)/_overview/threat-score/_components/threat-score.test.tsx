import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ThreatScore } from "./threat-score";
import { ThreatScoreSkeleton } from "./threat-score.skeleton";

describe("ThreatScore", () => {
  it("keeps the card compact when the overview row is horizontal", () => {
    // Given / When
    render(<ThreatScore score={75} />);

    const card = screen
      .getByText("Prowler ThreatScore")
      .closest('[data-slot="card"]');

    // Then
    expect(card).toHaveClass("w-full", "min-w-0", "lg:max-w-[312px]");
    ["max-w-[312px]", "xl:max-w-[312px]", "min-[485px]:min-w-[312px]"].forEach(
      (className) => expect(card).not.toHaveClass(className),
    );
  });

  it("keeps the skeleton width aligned with the loaded card", () => {
    // Given
    const { container, rerender } = render(<ThreatScoreSkeleton />);
    const skeletonCard = container.querySelector('[data-slot="card"]');
    const skeletonClassName = skeletonCard?.className;

    // When
    rerender(<ThreatScore score={75} />);
    const loadedCard = screen
      .getByText("Prowler ThreatScore")
      .closest('[data-slot="card"]');

    // Then
    expect(skeletonClassName).toBeDefined();
    expect(loadedCard?.className.split(" ").sort()).toEqual(
      skeletonClassName?.split(" ").sort(),
    );
  });
});
