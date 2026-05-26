import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Button } from "./button";

describe("shadcn Button", () => {
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
