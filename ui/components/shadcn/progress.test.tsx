import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Progress } from "./progress";

describe("Progress", () => {
  it("animates progress value changes with a transform-only transition", () => {
    // Given
    render(<Progress aria-label="Scan progress" value={40} />);

    // When
    const root = screen.getByRole("progressbar", { name: /scan progress/i });
    const indicator = root.querySelector("[data-slot='progress-indicator']");

    // Then
    expect(root).toHaveClass(
      "transition-colors",
      "duration-200",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(indicator).toHaveClass(
      "transition-transform",
      "duration-300",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(indicator).toHaveStyle({ transform: "translateX(-60%)" });
  });
});
