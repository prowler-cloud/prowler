import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { Combobox } from "./combobox";

const options = [
  { value: "aws", label: "AWS" },
  { value: "azure", label: "Azure" },
  { value: "gcp", label: "GCP" },
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

  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
});

describe("Combobox", () => {
  it("renders a selectable combobox trigger", () => {
    // Given
    render(<Combobox options={options} placeholder="Select provider" />);

    // When
    const trigger = screen.getByRole("combobox", { name: /select provider/i });

    // Then
    expect(trigger).toBeVisible();
    expect(trigger).toHaveAttribute("aria-expanded", "false");
  });

  it("uses visible trigger and chevron open-state motion", () => {
    // Given
    render(<Combobox options={options} placeholder="Select provider" />);

    // When
    const trigger = screen.getByRole("combobox", { name: /select provider/i });
    const icon = trigger.querySelector("svg");

    // Then
    expect(trigger).toHaveClass(
      "group",
      "transition-[background-color,border-color,color,box-shadow]",
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

  it("animates option rows and selected check indicators as internal feedback", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <Combobox value="aws" options={options} placeholder="Select provider" />,
    );

    // When
    await user.click(screen.getByRole("combobox", { name: /aws/i }));
    const selectedItem = screen.getByRole("option", { name: /aws/i });
    const unselectedItem = screen.getByRole("option", { name: /azure/i });
    const selectedCheck = selectedItem.querySelector("svg");
    const unselectedCheck = unselectedItem.querySelector("svg");

    // Then
    expect(selectedItem).toHaveClass(
      "transition-[background-color,color]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(selectedCheck).toHaveClass(
      "transition-[opacity,scale]",
      "duration-150",
      "ease-out",
      "scale-100",
      "opacity-100",
      "motion-reduce:scale-100",
      "motion-reduce:transition-none",
    );
    expect(unselectedCheck).toHaveClass("scale-95", "opacity-0");
  });

  it("opens with the shared Popover content motion contract", async () => {
    // Given
    const user = userEvent.setup();
    render(<Combobox options={options} placeholder="Select provider" />);

    // When
    await user.click(
      screen.getByRole("combobox", { name: /select provider/i }),
    );
    const content = document.querySelector("[data-slot='popover-content']");

    // Then
    expect(content).toHaveClass(
      "duration-200",
      "ease-out",
      "data-[state=open]:animate-in",
      "data-[state=open]:fade-in-0",
      "data-[state=open]:zoom-in-95",
      "motion-reduce:animate-none",
      "motion-reduce:transform-none",
      "motion-reduce:transition-none",
    );
  });
});
