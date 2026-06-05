import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { EnhancedMultiSelect } from "./enhanced-multi-select";

const options = [
  { value: "aws-prod", label: "Production AWS" },
  { value: "azure-dev", label: "Development Azure" },
];

beforeAll(() => {
  global.ResizeObserver = class ResizeObserver {
    observe = vi.fn();
    unobserve = vi.fn();
    disconnect = vi.fn();
  } as unknown as typeof ResizeObserver;

  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: vi.fn(),
  });
});

describe("EnhancedMultiSelect", () => {
  it("uses visible trigger and chevron open-state motion", () => {
    render(
      <EnhancedMultiSelect
        options={options}
        onValueChange={() => {}}
        placeholder="Select providers"
        aria-label="Select providers"
      />,
    );

    const trigger = screen.getByRole("combobox", { name: /select providers/i });
    const icon = trigger.querySelector("svg");

    expect(trigger).toHaveClass(
      "group",
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

  it("animates item selection feedback and checkbox visibility", async () => {
    const user = userEvent.setup();

    render(
      <EnhancedMultiSelect
        options={options}
        onValueChange={() => {}}
        placeholder="Select providers"
        aria-label="Select providers"
      />,
    );

    await user.click(
      screen.getByRole("combobox", { name: /select providers/i }),
    );

    const option = screen.getByRole("option", { name: /production aws/i });
    const checkbox = option.querySelector("[data-slot='checkbox']");
    const checkboxIndicator = checkbox?.querySelector(
      "[data-slot='checkbox-indicator']",
    );

    expect(option).toHaveClass(
      "transition-colors",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(checkbox).toHaveClass(
      "transition-colors",
      "duration-200",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(checkboxIndicator).toHaveClass(
      "transition-[opacity,transform]",
      "duration-200",
      "ease-out",
      "data-[state=checked]:scale-100",
      "data-[state=checked]:opacity-100",
      "data-[state=unchecked]:scale-75",
      "data-[state=unchecked]:opacity-0",
      "motion-reduce:transition-none",
    );
  });

  it("animates selected pills when values are added to the trigger", async () => {
    const user = userEvent.setup();
    const onValueChange = vi.fn();

    render(
      <EnhancedMultiSelect
        options={options}
        onValueChange={onValueChange}
        placeholder="Select providers"
        aria-label="Select providers"
      />,
    );

    await user.click(
      screen.getByRole("combobox", { name: /select providers/i }),
    );
    await user.click(screen.getByRole("option", { name: /production aws/i }));

    const pill = within(
      screen.getByRole("combobox", { name: /select providers/i }),
    )
      .getByText("Production AWS")
      .closest("[data-slot='enhanced-multiselect-pill']");

    expect(onValueChange).toHaveBeenCalledWith(["aws-prod"]);
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
});
