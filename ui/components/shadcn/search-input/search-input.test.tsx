import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { getClearButtonMotion, SearchInput } from "./search-input";

describe("getClearButtonMotion", () => {
  it("animates with scale when motion is allowed", () => {
    // Given / When
    const motion = getClearButtonMotion(false);

    // Then
    expect(motion.animate).toHaveProperty("scale", 1);
    expect(motion.initial).toHaveProperty("scale");
    expect(motion.exit).toHaveProperty("scale");
    expect(motion.transition.duration).toBeGreaterThan(0);
  });

  it("degrades to opacity-only with no scale under reduced motion", () => {
    // Given / When
    const motion = getClearButtonMotion(true);

    // Then
    expect(motion.initial).not.toHaveProperty("scale");
    expect(motion.animate).not.toHaveProperty("scale");
    expect(motion.exit).not.toHaveProperty("scale");
    expect(motion.transition.duration).toBe(0);
  });
});

describe("SearchInput", () => {
  it("animates input focus, icon color, and clear button entry", () => {
    // Given - A search input with a clear action
    render(
      <SearchInput
        aria-label="Search findings"
        value="cloudflare"
        readOnly
        onClear={vi.fn()}
      />,
    );

    // When - The search field has a value
    const input = screen.getByRole("textbox", { name: /search findings/i });
    const clearButton = screen.getByRole("button", { name: /clear search/i });
    const searchIcon = input.parentElement?.querySelector("svg");

    // Then - Search-specific affordances have visible motion
    expect(input).toHaveClass(
      "transition-[background-color,border-color,box-shadow,color]",
      "duration-250",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(searchIcon).toHaveClass(
      "transition-colors",
      "duration-250",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(clearButton).toHaveAttribute("data-slot", "search-input-clear");
    expect(clearButton).toHaveClass(
      "transition-colors",
      "duration-250",
      "ease-out",
      "motion-reduce:transition-none",
    );
  });
});
