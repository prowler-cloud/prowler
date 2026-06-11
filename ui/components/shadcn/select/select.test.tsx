import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./select";

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: vi.fn(),
  });
});

afterEach(() => {
  vi.useRealTimers();
});

function renderTypeSelect({ open = false }: { open?: boolean } = {}) {
  return render(
    <Select defaultValue="all" open={open} onValueChange={() => {}}>
      <SelectTrigger aria-label="All Types">
        <SelectValue placeholder="All Types" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">All Types</SelectItem>
        <SelectItem value="manual">Manual</SelectItem>
        <SelectItem value="scheduled">Scheduled</SelectItem>
      </SelectContent>
    </Select>,
  );
}

describe("Select", () => {
  it("renders an open dropdown with selectable options", () => {
    // Given
    renderTypeSelect({ open: true });

    // When
    const listbox = screen.getByRole("listbox");

    // Then
    expect(
      within(listbox).getByRole("option", { name: "All Types" }),
    ).toBeVisible();
    expect(
      within(listbox).getByRole("option", { name: "Manual" }),
    ).toBeVisible();
    expect(
      within(listbox).getByRole("option", { name: "Scheduled" }),
    ).toBeVisible();
  });

  it("uses robust trigger transitions for hover, focus, and chevron state", () => {
    // Given
    renderTypeSelect();

    // When
    const trigger = screen.getByRole("combobox", { name: "All Types" });
    const icon = trigger.querySelector("svg");

    // Then
    expect(trigger).toHaveClass(
      "transition-[background-color,border-color,color,box-shadow]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(icon).toHaveClass(
      "transition-[rotate]",
      "duration-200",
      "ease-out",
      "group-data-[state=open]:rotate-180",
      "motion-reduce:rotate-0",
      "motion-reduce:transition-none",
    );
  });

  it("preserves the Radix open data-state model", () => {
    // Given
    renderTypeSelect({ open: true });

    // When
    const listbox = screen.getByRole("listbox");
    const content = listbox.closest("[data-slot='select-content']");

    // Then
    expect(content).toHaveAttribute("data-state", "open");
  });

  it("keeps content mounted briefly with a closing state", async () => {
    // Given
    const { rerender } = renderTypeSelect({ open: true });

    expect(screen.getByRole("listbox")).toBeVisible();

    // When
    rerender(
      <Select defaultValue="all" open={false} onValueChange={() => {}}>
        <SelectTrigger aria-label="All Types">
          <SelectValue placeholder="All Types" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Types</SelectItem>
          <SelectItem value="manual">Manual</SelectItem>
          <SelectItem value="scheduled">Scheduled</SelectItem>
        </SelectContent>
      </Select>,
    );

    // Then
    const content = await waitFor(() =>
      screen.getByRole("listbox").closest("[data-slot='select-content']"),
    );
    const trigger = document.querySelector("[data-slot='select-trigger']");

    expect(content).toHaveAttribute("data-closing", "true");
    expect(trigger).toHaveAttribute("data-closing", "true");

    await waitFor(() => {
      expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    });
  });

  it("keeps uncontrolled content mounted briefly after selecting an option", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <Select defaultOpen defaultValue="all" onValueChange={() => {}}>
        <SelectTrigger aria-label="All Types">
          <SelectValue placeholder="All Types" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Types</SelectItem>
          <SelectItem value="manual">Manual</SelectItem>
          <SelectItem value="scheduled">Scheduled</SelectItem>
        </SelectContent>
      </Select>,
    );

    expect(screen.getByRole("listbox")).toBeVisible();

    // When
    await user.click(screen.getByRole("option", { name: "Manual" }));

    // Then
    const content = await waitFor(() =>
      screen.getByRole("listbox").closest("[data-slot='select-content']"),
    );
    const trigger = document.querySelector("[data-slot='select-trigger']");

    expect(content).toHaveAttribute("data-closing", "true");
    expect(content).toHaveClass(
      "animate-out",
      "fade-out-0",
      "zoom-out-95",
      "pointer-events-none",
      "duration-100",
      "ease-in",
    );
    expect(content).not.toHaveClass(
      "data-[state=open]:animate-in",
      "data-[state=open]:fade-in-0",
      "data-[state=open]:zoom-in-95",
    );
    expect(trigger).toHaveAttribute("data-closing", "true");
  });

  it("animates option rows and selected check indicators as internal feedback", () => {
    // Given
    renderTypeSelect({ open: true });

    // When
    const selectedOption = screen.getByRole("option", { name: "All Types" });
    const checkIcon = selectedOption.querySelector("svg");

    // Then
    expect(selectedOption).toHaveClass(
      "transition-colors",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(checkIcon).toHaveClass(
      "animate-in",
      "fade-in-0",
      "zoom-in-75",
      "duration-150",
      "ease-out",
      "motion-reduce:animate-none",
    );
  });

  it("uses explicit open and close motion classes", () => {
    // Given
    renderTypeSelect({ open: true });

    // When
    const content = screen
      .getByRole("listbox")
      .closest("[data-slot='select-content']");

    // Then
    expect(content).toHaveClass(
      "data-[state=open]:animate-in",
      "data-[state=closed]:animate-out",
      "data-[state=open]:fade-in-0",
      "data-[state=closed]:fade-out-0",
      "data-[state=open]:zoom-in-95",
      "data-[state=closed]:zoom-out-95",
      "duration-200",
      "ease-out",
      "data-[state=closed]:duration-100",
      "data-[state=closed]:ease-in",
    );
  });

  it("removes transform-heavy dropdown motion for reduced motion", () => {
    // Given
    renderTypeSelect({ open: true });

    // When
    const content = screen
      .getByRole("listbox")
      .closest("[data-slot='select-content']");

    // Then
    expect(content).toHaveClass(
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });
});
