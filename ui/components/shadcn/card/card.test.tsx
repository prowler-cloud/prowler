import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Card } from "./card";

describe("Card", () => {
  it("uses semantic fail colors for danger cards instead of dark RGBA colors in light mode", () => {
    // Given
    render(
      <Card variant="danger" data-testid="danger-card">
        Risk
      </Card>,
    );

    // When
    const card = screen.getByTestId("danger-card");

    // Then
    expect(card).toHaveClass("border-border-error");
    expect(card).toHaveClass("bg-bg-fail-secondary");
    expect(card.className).not.toContain("rgba(67,34,50");
  });
});
