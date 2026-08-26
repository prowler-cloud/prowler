import { useState } from "react";
import { describe, expect, it } from "vitest";
import { userEvent } from "vitest/browser";

import { render } from "@/__tests__/render-browser";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from "../dialog";

function DialogHarness() {
  const [open, setOpen] = useState(false);

  return (
    <Dialog onOpenChange={setOpen} open={open}>
      <DialogTrigger asChild>
        <button type="button">Open dialog</button>
      </DialogTrigger>
      <DialogContent>
        <DialogTitle>Dialog title</DialogTitle>
        <DialogDescription>Dialog description</DialogDescription>
        <button type="button">Dialog first control</button>
      </DialogContent>
    </Dialog>
  );
}

describe("Dialog", () => {
  it("honors reduced motion at its overlay and content while keeping keyboard focus restoration", async () => {
    // Given
    const screen = await render(<DialogHarness />);
    const trigger = screen.getByRole("button", { name: "Open dialog" });

    // When
    await trigger.click();

    // Then
    const overlay = document.querySelector('[data-slot="dialog-overlay"]');
    expect(overlay).not.toBeNull();
    expect(overlay!).toHaveClass(
      "motion-reduce:animate-none",
      "motion-reduce:transition-none",
      "motion-reduce:duration-0",
    );
    await expect
      .element(screen.getByRole("dialog"))
      .toHaveClass(
        "motion-reduce:animate-none",
        "motion-reduce:transition-none",
        "motion-reduce:duration-0",
      );
    await expect
      .element(screen.getByRole("button", { name: "Dialog first control" }))
      .toHaveFocus();

    // When
    await userEvent.keyboard("{Escape}");

    // Then
    await expect.element(trigger).toHaveFocus();
  });
});
