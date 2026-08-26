import { useState } from "react";
import { describe, expect, it } from "vitest";
import { userEvent } from "vitest/browser";

import { render } from "@/__tests__/render-browser";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
  SheetTrigger,
} from "./sheet";

function SheetHarness() {
  const [open, setOpen] = useState(false);

  return (
    <Sheet onOpenChange={setOpen} open={open}>
      <SheetTrigger asChild>
        <button type="button">Open sheet</button>
      </SheetTrigger>
      <SheetContent side="left">
        <SheetTitle>Sheet title</SheetTitle>
        <SheetDescription>Sheet description</SheetDescription>
        <button type="button">Sheet first control</button>
      </SheetContent>
    </Sheet>
  );
}

describe("Sheet", () => {
  it("honors reduced motion at its overlay and content while keeping keyboard focus restoration", async () => {
    // Given
    const screen = await render(<SheetHarness />);
    const trigger = screen.getByRole("button", { name: "Open sheet" });

    // When
    await trigger.click();

    // Then
    const overlay = document.querySelector(
      '[data-state="open"][class*="bg-black"]',
    );
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
      .element(screen.getByRole("button", { name: "Close" }))
      .toHaveFocus();

    // When
    await userEvent.keyboard("{Escape}");
    // Then
    await expect.element(trigger).toHaveFocus();
  });
});
