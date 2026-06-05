import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Button } from "./button";

describe("Button", () => {
  it("uses semibold text for primary buttons", () => {
    const { rerender } = render(<Button>Primary</Button>);

    expect(screen.getByRole("button", { name: "Primary" })).toHaveClass(
      "font-semibold",
    );

    rerender(<Button variant="outline">Outline</Button>);

    expect(screen.getByRole("button", { name: "Outline" })).toHaveClass(
      "font-medium",
    );
    expect(screen.getByRole("button", { name: "Outline" })).not.toHaveClass(
      "font-semibold",
    );
  });

  it("supports extra-small link buttons", () => {
    render(
      <Button variant="link" size="link-xs">
        Open link
      </Button>,
    );

    expect(screen.getByRole("button", { name: "Open link" })).toHaveClass(
      "text-xs",
    );
  });

  it("applies the shared press and reduced-motion contract to button-like variants", () => {
    // Given
    render(<Button>Start scan</Button>);

    // When
    const button = screen.getByRole("button", { name: "Start scan" });

    // Then
    expect(button).toHaveClass(
      "transition-[background-color,border-color,color,box-shadow,transform,scale]",
      "duration-150",
      "ease-out",
      "active:scale-[0.98]",
      "motion-reduce:active:scale-100",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
    expect(button).not.toHaveClass("transition-all");
  });

  it("keeps link buttons from scaling on press", () => {
    // Given
    render(<Button variant="link">Open details</Button>);

    // When
    const button = screen.getByRole("button", { name: "Open details" });

    // Then
    expect(button).toHaveClass("active:scale-100");
    expect(button).not.toHaveClass("active:scale-[0.98]");
  });

  it("keeps menu buttons on the shared targeted transition recipe", () => {
    // Given
    render(<Button variant="menu">Open menu</Button>);

    // When
    const button = screen.getByRole("button", { name: "Open menu" });

    // Then
    expect(button).toHaveClass(
      "transition-[background-color,border-color,color,box-shadow,transform,scale]",
      "duration-200",
      "active:scale-[0.98]",
      "motion-reduce:active:scale-100",
    );
    expect(button).not.toHaveClass("transition-all");
  });
});
