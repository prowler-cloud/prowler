import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it } from "vitest";

import { Select, SelectContent, SelectItem, SelectTrigger } from "./select";

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: () => false,
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: () => {},
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: () => {},
  });
});

describe("Select", () => {
  it("supports an extra-small trigger size", () => {
    // Given / When
    render(
      <Select value="open">
        <SelectTrigger aria-label="Compact status" size="xs">
          Open
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="open">Open</SelectItem>
        </SelectContent>
      </Select>,
    );

    // Then
    const trigger = screen.getByRole("combobox", { name: "Compact status" });
    expect(trigger).toHaveAttribute("data-size", "xs");
    expect(trigger).toHaveClass(
      "data-[size=xs]:h-8",
      "data-[size=xs]:px-3",
      "data-[size=xs]:py-0",
      "data-[size=xs]:text-xs",
    );
  });

  it("uses a selected background instead of a check icon for the active item", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <Select value="under_review">
        <SelectTrigger aria-label="Triage status">Under Review</SelectTrigger>
        <SelectContent>
          <SelectItem value="open">Open</SelectItem>
          <SelectItem value="under_review">Under Review</SelectItem>
        </SelectContent>
      </Select>,
    );

    // When
    await user.click(screen.getByRole("combobox", { name: "Triage status" }));

    // Then
    const selectedItem = screen.getByRole("option", {
      name: "Under Review",
    });
    expect(selectedItem).toHaveAttribute("data-state", "checked");
    expect(selectedItem).toHaveClass(
      "data-[state=checked]:bg-button-tertiary/10",
    );
    expect(selectedItem).not.toHaveClass(
      "data-[state=checked]:bg-bg-neutral-tertiary",
    );
    expect(selectedItem).toHaveClass(
      "data-[state=checked]:hover:bg-button-tertiary/15",
    );
    expect(selectedItem).toHaveClass("hover:bg-slate-200");
    expect(selectedItem).toHaveClass("dark:hover:bg-slate-700/50");
    expect(
      within(selectedItem).queryByRole("img", { hidden: true }),
    ).toBeNull();
    expect(selectedItem.querySelector("svg")).toBeNull();
  });
});
