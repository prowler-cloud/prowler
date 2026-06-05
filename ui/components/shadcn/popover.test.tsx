import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { Popover, PopoverContent, PopoverTrigger } from "./popover";

describe("Popover", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("renders controlled content through the Radix Popover API", () => {
    // Given
    const portalContainer = document.createElement("div");
    document.body.appendChild(portalContainer);

    // When
    render(
      <Popover open>
        <PopoverTrigger>Open filters</PopoverTrigger>
        <PopoverContent container={portalContainer}>
          Filter content
        </PopoverContent>
      </Popover>,
    );

    // Then
    expect(screen.getByText("Filter content")).toBeVisible();
    expect(screen.getByText("Filter content")).toHaveAttribute(
      "data-slot",
      "popover-content",
    );
  });

  it("uses an intentional open and close motion contract", () => {
    // Given
    const portalContainer = document.createElement("div");
    document.body.appendChild(portalContainer);

    // When
    render(
      <Popover open>
        <PopoverTrigger>Open filters</PopoverTrigger>
        <PopoverContent container={portalContainer}>
          Filter content
        </PopoverContent>
      </Popover>,
    );

    // Then
    expect(screen.getByText("Filter content")).toHaveClass(
      "origin-(--radix-popover-content-transform-origin)",
      "duration-200",
      "ease-out",
      "data-[state=open]:animate-in",
      "data-[state=open]:fade-in-0",
      "data-[state=open]:zoom-in-95",
      "data-[state=closed]:animate-out",
      "data-[state=closed]:fade-out-0",
      "data-[state=closed]:zoom-out-95",
      "data-[state=closed]:duration-100",
      "data-[state=closed]:ease-in",
    );
  });

  it("removes transform-heavy motion for reduced-motion users", () => {
    // Given
    const portalContainer = document.createElement("div");
    document.body.appendChild(portalContainer);

    // When
    render(
      <Popover open>
        <PopoverTrigger>Open filters</PopoverTrigger>
        <PopoverContent container={portalContainer}>
          Filter content
        </PopoverContent>
      </Popover>,
    );

    // Then
    expect(screen.getByText("Filter content")).toHaveClass(
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });
});
