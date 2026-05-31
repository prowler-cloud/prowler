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
});
