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
      "data-[state=open]:animate-collapsible-down",
      "data-[state=closed]:animate-collapsible-up",
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
      "motion-reduce:transition-none",
    );
  });
});
