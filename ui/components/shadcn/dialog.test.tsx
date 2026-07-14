import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Dialog, DialogContent, DialogTitle } from "./dialog";

describe("DialogContent", () => {
  it("should highlight keyboard focus without drawing a close ring", () => {
    // Given / When
    render(
      <Dialog open>
        <DialogContent aria-describedby={undefined}>
          <DialogTitle>Example dialog</DialogTitle>
        </DialogContent>
      </Dialog>,
    );

    const closeButton = screen.getByRole("button", { name: "Close" });

    // Then
    expect(closeButton).toHaveClass(
      "focus-visible:bg-bg-neutral-tertiary",
      "focus-visible:opacity-100",
    );
    expect(closeButton).not.toHaveClass("focus-visible:ring-2");
    expect(closeButton).not.toHaveClass("focus-visible:ring-offset-2");
    expect(closeButton).not.toHaveClass("focus:ring-2");
  });
});
