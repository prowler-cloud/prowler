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

  it("uses visible trigger and chevron open-state motion", () => {
    render(
      <MultiSelect values={[]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    const trigger = screen.getByRole("combobox");
    const icon = trigger.querySelector("svg");

    expect(trigger).toHaveClass(
      "transition-[background-color,border-color,color,box-shadow]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(icon).toHaveClass(
      "transition-transform",
      "duration-200",
      "ease-out",
      "group-aria-expanded:rotate-180",
      "motion-reduce:rotate-0",
      "motion-reduce:transition-none",
    );
  });

  it("uses visible content open and close motion", async () => {
    const user = userEvent.setup();

    render(
      <MultiSelect values={[]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));

    const content = document.querySelector("[data-slot='multiselect-content']");

    expect(content).toHaveClass(
      "duration-200",
      "ease-out",
      "data-[state=open]:animate-in",
      "data-[state=open]:fade-in-0",
      "data-[state=open]:zoom-in-95",
      "data-[state=closed]:animate-out",
      "data-[state=closed]:fade-out-0",
      "data-[state=closed]:zoom-out-95",
      "data-[state=closed]:duration-100",
      "data-[state=closed]:ease-in",
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });

  it("animates item selection feedback and check visibility", async () => {
    const user = userEvent.setup();

    render(
      <MultiSelect defaultValues={[]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));

    const option = screen.getByRole("option", { name: /production aws/i });
    const checkIcon = option.querySelector("svg");

    expect(option).toHaveClass(
      "transition-colors",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(checkIcon).toHaveClass(
      "transition-[opacity,transform]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
  });

  it("animates selected pills when values are added to the trigger", async () => {
    const user = userEvent.setup();

    render(
      <MultiSelect defaultValues={[]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectItem value="aws-prod">Production AWS</MultiSelectItem>
        </MultiSelectContent>
      </MultiSelect>,
    );

    await user.click(screen.getByRole("combobox"));
    await user.click(screen.getByRole("option", { name: /production aws/i }));

    const pill = within(screen.getByRole("combobox"))
      .getByText("Production AWS")
      .closest("[data-selected-item]");

    expect(pill).toHaveClass(
      "animate-in",
      "fade-in-0",
      "zoom-in-95",
      "duration-150",
      "ease-out",
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
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

  it("closes the dropdown when clicking outside", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <div>
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
          </MultiSelectContent>
        </MultiSelect>
        <button type="button">Outside target</button>
      </div>,
    );

    // When
    await user.click(screen.getByRole("combobox"));
    expect(screen.getByPlaceholderText("Search accounts...")).toBeVisible();
    await user.click(screen.getByRole("button", { name: /outside target/i }));

    // Then
    expect(
      screen.queryByPlaceholderText("Search accounts..."),
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

  it("keeps long option lists scrollable inside the dropdown", async () => {
    // Given
    const user = userEvent.setup();

    render(
      <MultiSelect values={[]} onValuesChange={() => {}}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder="Select accounts" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          {Array.from({ length: 20 }, (_, index) => (
            <MultiSelectItem key={index} value={`account-${index}`}>
              Account {index}
            </MultiSelectItem>
          ))}
        </MultiSelectContent>
      </MultiSelect>,
    );

    // When
    await user.click(screen.getByRole("combobox"));

    // Then
    const list = screen
      .getByRole("dialog")
      .querySelector('[data-slot="command-list"]');

    expect(screen.getByRole("dialog")).toHaveStyle({
      maxHeight:
        "min(360px, var(--radix-popover-content-available-height, 360px))",
    });
    expect(list).toHaveClass("minimal-scrollbar");
    expect(list).toHaveStyle({
      maxHeight:
        "min(300px, var(--radix-popover-content-available-height, 300px))",
    });
    expect(list).toHaveClass("overflow-y-auto");
    expect(list).toHaveClass("overscroll-contain");
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
