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

  it("supports extra-small icon buttons", () => {
    render(
      <Button size="icon-xs" aria-label="Open tour">
        Open tour
      </Button>,
    );

    expect(screen.getByRole("button", { name: "Open tour" })).toHaveClass(
      "size-7",
    );
  });

  it("renders the bare variant chrome-free (no background or border)", () => {
    render(
      <Button variant="bare" size="icon-sm" aria-label="Toggle sidebar">
        <svg />
      </Button>,
    );

    const button = screen.getByRole("button", { name: "Toggle sidebar" });
    expect(button).toHaveClass("bg-transparent");
    expect(button).toHaveClass("border-0");
    expect(button).toHaveClass("p-0");
  });
});
