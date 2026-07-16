import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "./sheet";

describe("SheetContent", () => {
  it("exposes the navigation drawer variant as a design-system contract", () => {
    // Given / When
    render(
      <Sheet open>
        <SheetContent variant="navigation" showCloseButton={false}>
          <SheetHeader>
            <SheetTitle>App navigation</SheetTitle>
            <SheetDescription>Primary destinations</SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>,
    );

    // Then
    expect(
      screen.getByRole("dialog", { name: "App navigation" }),
    ).toHaveAttribute("data-variant", "navigation");
  });
});
