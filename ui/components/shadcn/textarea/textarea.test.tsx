import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Textarea } from "./textarea";

describe("Textarea", () => {
  it("uses visible hover and focus microinteraction timing", () => {
    // Given - A standard textarea
    render(<Textarea aria-label="Reason" />);

    // When - The textarea renders
    const textarea = screen.getByRole("textbox", { name: /reason/i });

    // Then - The focus/hover state changes are intentionally timed
    expect(textarea).toHaveClass(
      "transition-[background-color,border-color,box-shadow,color]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
  });
});
