import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Card, CardHeader } from "./card";

describe("CardHeader", () => {
  it("does not add vertical margin by default", () => {
    // Given - A default card header
    render(<CardHeader>Header</CardHeader>);

    // When - Reading the rendered header
    const header = screen.getByText("Header");

    // Then - Card spacing is controlled by the card gap or caller styles
    expect(header).not.toHaveClass("mb-6");
  });
});

describe("Card", () => {
  it("provides the shared interactive treatment without call-site classes", () => {
    render(<Card interactive>Framework</Card>);

    expect(screen.getByText("Framework")).toHaveClass(
      "cursor-pointer",
      "transition-shadow",
      "hover:shadow-md",
    );
  });
});
