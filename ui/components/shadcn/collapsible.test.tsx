import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "./collapsible";

describe("Collapsible", () => {
  it("uses an intentional open and close motion contract", () => {
    // Given
    render(
      <Collapsible open>
        <CollapsibleTrigger>Toggle details</CollapsibleTrigger>
        <CollapsibleContent>Expandable content</CollapsibleContent>
      </Collapsible>,
    );

    // When
    const content = screen.getByText("Expandable content");

    // Then
    expect(content).toHaveAttribute("data-slot", "collapsible-content");
    expect(content).toHaveClass(
      "overflow-hidden",
      "duration-200",
      "ease-out",
      "data-[state=open]:animate-in",
      "data-[state=open]:fade-in-0",
      "data-[state=open]:slide-in-from-top-1",
      "data-[state=closed]:animate-out",
      "data-[state=closed]:fade-out-0",
      "data-[state=closed]:slide-out-to-top-1",
      "data-[state=closed]:duration-150",
      "data-[state=closed]:ease-in",
    );
  });

  it("removes transform-heavy motion for reduced-motion users", () => {
    // Given
    render(
      <Collapsible open>
        <CollapsibleTrigger>Toggle details</CollapsibleTrigger>
        <CollapsibleContent>Expandable content</CollapsibleContent>
      </Collapsible>,
    );

    // When
    const content = screen.getByText("Expandable content");

    // Then
    expect(content).toHaveClass(
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });
});
