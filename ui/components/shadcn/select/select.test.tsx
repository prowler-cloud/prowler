import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./select";

Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
  writable: true,
  configurable: true,
  value: () => false,
});

Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
  writable: true,
  configurable: true,
  value: () => {},
});

describe("Select", () => {
  it("keeps long option lists scrollable inside the dropdown", async () => {
    // Given
    const user = userEvent.setup();

    render(
      <Select defaultValue="option-1">
        <SelectTrigger aria-label="Options">
          <SelectValue placeholder="Select option" />
        </SelectTrigger>
        <SelectContent>
          {Array.from({ length: 20 }, (_, index) => (
            <SelectItem key={index} value={`option-${index}`}>
              Option {index}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>,
    );

    // When
    await user.click(screen.getByRole("combobox", { name: /options/i }));

    // Then
    const viewport = screen
      .getByRole("listbox")
      .querySelector('[data-slot="select-viewport"]');
    expect(screen.getByRole("listbox")).toHaveStyle({
      maxHeight: "var(--radix-select-content-available-height)",
    });
    expect(viewport).toHaveClass("minimal-scrollbar");
    expect(viewport).toHaveStyle({
      maxHeight:
        "min(300px, var(--radix-select-content-available-height, 300px))",
    });
    expect(viewport).toHaveClass("overflow-y-auto");
    expect(viewport).toHaveClass("overscroll-contain");
  });
});
