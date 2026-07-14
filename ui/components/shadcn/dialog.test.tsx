import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Dialog, DialogContent, DialogTitle } from "./dialog";

describe("DialogContent", () => {
  it("should only show the close focus ring for keyboard navigation", () => {
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
    expect(closeButton).toHaveClass("focus-visible:ring-2");
    expect(closeButton).not.toHaveClass("focus:ring-2");
  });
});
