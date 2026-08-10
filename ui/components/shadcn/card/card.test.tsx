import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CardHeader } from "./card";

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
