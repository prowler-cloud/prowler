import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Tooltip, TooltipContent, TooltipTrigger } from "./tooltip";

function renderOpenTooltip() {
  return render(
    <Tooltip open>
      <TooltipTrigger>Copy ARN</TooltipTrigger>
      <TooltipContent>Copy resource identifier</TooltipContent>
    </Tooltip>,
  );
}

describe("Tooltip", () => {
  it("renders controlled content through the Radix Tooltip API", () => {
    // Given
    renderOpenTooltip();

    // When
    const tooltip = document.querySelector("[data-slot='tooltip-content']");

    // Then
    expect(screen.getByRole("tooltip")).toBeVisible();
    expect(tooltip).toBeVisible();
    expect(tooltip).toHaveTextContent("Copy resource identifier");
  });

  it("uses an intentional open and close motion contract", () => {
    // Given
    renderOpenTooltip();

    // When
    const tooltip = document.querySelector("[data-slot='tooltip-content']");

    // Then
    expect(tooltip).toHaveClass(
      "origin-(--radix-tooltip-content-transform-origin)",
      "animate-in",
      "fade-in-0",
      "zoom-in-95",
      "duration-150",
      "ease-out",
      "data-[state=closed]:animate-out",
      "data-[state=closed]:fade-out-0",
      "data-[state=closed]:zoom-out-95",
      "data-[state=closed]:duration-100",
      "data-[state=closed]:ease-in",
    );
  });

  it("removes transform-heavy tooltip motion for reduced-motion users", () => {
    // Given
    renderOpenTooltip();

    // When
    const tooltip = document.querySelector("[data-slot='tooltip-content']");

    // Then
    expect(tooltip).toHaveClass(
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });
});
