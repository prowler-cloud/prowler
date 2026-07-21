import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectSelectAll,
  MultiSelectTrigger,
  MultiSelectValue,
} from "./multiselect";

const scrollIntoViewMock = vi.fn();

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
  value: scrollIntoViewMock,
});

describe("MultiSelect", () => {
  beforeEach(() => {
    scrollIntoViewMock.mockClear();
  });

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
    expect(
      within(screen.getByRole("combobox")).queryByText("Select accounts"),
    ).not.toBeInTheDocument();
  });

  it("keeps the filter label context when a value is selected", () => {
    render(
      <MultiSelect values={["FAIL"]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="All Status" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectItem value="FAIL">FAIL</MultiSelectItem>
          <MultiSelectItem value="PASS">PASS</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    expect(
      within(screen.getByRole("combobox")).getByText("Status"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole("combobox")).getByText("FAIL"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole("combobox")).queryByText("All Status"),
    ).not.toBeInTheDocument();
  });

  it("uses a selected background instead of a check icon for active items", async () => {
    // Given
    const user = userEvent.setup();
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

    // When
    await user.click(screen.getByRole("combobox"));

    // Then
    const selectedItem = screen.getByRole("option", {
      name: "Production AWS",
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
    expect(selectedItem.querySelector("svg")).toBeNull();
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

  it("scrolls the first visible match into view when filtering", async () => {
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
          <MultiSelectItem value="azure-dev">Development Azure</MultiSelectItem>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));
    await user.type(screen.getByPlaceholderText("Search accounts..."), "aws");

    await waitFor(() => {
      expect(scrollIntoViewMock).toHaveBeenCalled();
    });
  });

  it("clears the search input when reopening the popover", async () => {
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

    const searchInput = screen.getByPlaceholderText(
      "Search accounts...",
    ) as HTMLInputElement;

    await user.type(searchInput, "aws");
    expect(searchInput).toHaveValue("aws");

    await user.keyboard("{Escape}");
    expect(
      screen.queryByPlaceholderText("Search accounts..."),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("combobox"));

    expect(screen.getByPlaceholderText("Search accounts...")).toHaveValue("");
  });

  it("sizes the dropdown to its content with a capped width", async () => {
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

    expect(screen.getByRole("dialog")).toHaveClass("sm:w-max");
    expect(screen.getByRole("dialog")).toHaveClass("sm:max-w-[22rem]");
  });

  it("keeps the legacy clear-all behavior by default", async () => {
    const user = userEvent.setup();
    const onValuesChange = vi.fn();

    render(
      <MultiSelect values={["aws-prod"]} onValuesChange={onValuesChange}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectSelectAll>Select All</MultiSelectSelectAll>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
          <MultiSelectItem value="azure-dev">Development Azure</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));
    await user.click(screen.getByRole("button", { name: /select all/i }));

    expect(onValuesChange).toHaveBeenCalledWith([]);
  });

  it("disables the legacy select all action when no filter is selected", async () => {
    const user = userEvent.setup();
    const onValuesChange = vi.fn();

    render(
      <MultiSelect values={[]} onValuesChange={onValuesChange}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectSelectAll>Select All</MultiSelectSelectAll>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
          <MultiSelectItem value="azure-dev">Development Azure</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));

    expect(
      screen.getByRole("button", { name: /all selected/i }),
    ).toBeDisabled();
  });

  it("selects every provided option when select mode is enabled", async () => {
    const user = userEvent.setup();
    const onValuesChange = vi.fn();

    render(
      <MultiSelect values={[]} onValuesChange={onValuesChange}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectSelectAll
            mode="select"
            values={["aws-prod", "azure-dev"]}
          >
            Select All
          </MultiSelectSelectAll>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
          <MultiSelectItem value="azure-dev">Development Azure</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));
    await user.click(screen.getByRole("button", { name: /select all/i }));

    expect(onValuesChange).toHaveBeenCalledWith(["aws-prod", "azure-dev"]);
  });

  it("does not select disabled options", async () => {
    const user = userEvent.setup();
    const onValuesChange = vi.fn();

    render(
      <MultiSelect values={[]} onValuesChange={onValuesChange}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
          <MultiSelectItem value="aws-disconnected" disabled>
            Disconnected AWS
          </MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));

    const disabledOption = screen.getByRole("option", {
      name: /disconnected aws/i,
    });

    expect(disabledOption).toHaveAttribute("data-disabled", "true");
    expect(disabledOption).toHaveAttribute("aria-disabled", "true");

    await user.click(disabledOption);

    expect(onValuesChange).not.toHaveBeenCalled();
  });
});
