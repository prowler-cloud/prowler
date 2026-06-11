import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { RadioGroup, RadioGroupItem } from "./radio-group";

describe("RadioGroup", () => {
  it("animates item state and indicator entry", async () => {
    // Given - A controlled radio group
    const user = userEvent.setup();
    const onValueChange = vi.fn();
    render(
      <RadioGroup value="aws" onValueChange={onValueChange}>
        <RadioGroupItem value="aws" aria-label="AWS" />
        <RadioGroupItem value="azure" aria-label="Azure" />
      </RadioGroup>,
    );

    // When - The user selects another radio option
    const azure = screen.getByRole("radio", { name: /azure/i });
    await user.click(azure);
    const indicator = azure.querySelector(
      "[data-slot='radio-group-indicator']",
    );

    // Then - The item and dot use synchronized visual feedback
    expect(azure).toHaveClass(
      "transition-[background-color,border-color,box-shadow]",
      "duration-200",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(indicator).toHaveClass(
      "transition-[opacity,transform]",
      "duration-200",
      "ease-out",
      "data-[state=checked]:scale-100",
      "data-[state=checked]:opacity-100",
      "data-[state=unchecked]:scale-75",
      "data-[state=unchecked]:opacity-0",
      "motion-reduce:transition-none",
    );
    expect(onValueChange).toHaveBeenCalledWith("azure");
  });
});
