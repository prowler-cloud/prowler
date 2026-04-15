import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
} from "./multiselect";

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", {
  writable: true,
  configurable: true,
  value: ResizeObserverMock,
});

Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
  writable: true,
  configurable: true,
  value: () => {},
});

describe("MultiSelect", () => {
  it("shows preselected labels before the popover opens", () => {
    // Given
    render(
      <MultiSelect values={["aws-prod"]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
          <MultiSelectItem value="azure-dev">Development Azure</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    // Then
    expect(
      within(screen.getByRole("combobox")).getByText("Production AWS"),
    ).toBeInTheDocument();
  });

  it("filters items without crashing when search is enabled", async () => {
    const user = userEvent.setup();

    render(
      <MultiSelect values={[]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent
          search={{
            placeholder: "Search accounts...",
            emptyMessage: "No accounts found.",
          }}
        >
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
          <MultiSelectItem value="azure-dev">Development Azure</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));
    await user.type(screen.getByPlaceholderText("Search accounts..."), "aws");

    expect(
      within(screen.getByRole("dialog")).getByText("Production AWS"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole("dialog")).queryByText("Development Azure"),
    ).not.toBeInTheDocument();
  });

  it("uses a normalized dropdown width instead of growing with the longest item", async () => {
    const user = userEvent.setup();

    render(
      <MultiSelect values={[]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectItem value="very-long-item">
            This is a very long option label that should not expand the dropdown
            indefinitely
          </MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));

    expect(screen.getByRole("dialog")).toHaveClass(
      "w-[min(var(--radix-popover-trigger-width),calc(100vw-2rem))]",
    );
    expect(screen.getByRole("dialog")).toHaveClass("max-w-[24rem]");
  });
});
