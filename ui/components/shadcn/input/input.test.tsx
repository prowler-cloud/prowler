import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Input } from "./input";

describe("Input", () => {
  it("uses visible hover and focus microinteraction timing", () => {
    // Given - A standard text input
    render(<Input aria-label="Alias" />);

    // When - The input renders
    const input = screen.getByRole("textbox", { name: /alias/i });

    // Then - The focus/hover state changes are intentionally timed
    expect(input).toHaveClass(
      "transition-[background-color,border-color,box-shadow,color]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
  });
});
