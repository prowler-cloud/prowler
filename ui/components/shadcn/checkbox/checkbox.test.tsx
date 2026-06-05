import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { Checkbox } from "./checkbox";

function ControlledCheckbox() {
  const [checked, setChecked] = useState(false);

  return (
    <Checkbox
      aria-label="Select provider"
      checked={checked}
      onCheckedChange={(value) => setChecked(value === true)}
    />
  );
}

describe("Checkbox", () => {
  it("animates the background and check mark as one state change", async () => {
    // Given - A controlled checkbox in the unchecked state
    const user = userEvent.setup();
    render(<ControlledCheckbox />);

    const checkbox = screen.getByRole("checkbox", { name: /select provider/i });
    const indicator = checkbox.querySelector(
      "[data-slot='checkbox-indicator']",
    );

    // When - The user checks the checkbox
    await user.click(checkbox);

    // Then - The background and check mark transitions use the same timing
    expect(checkbox).toHaveClass(
      "transition-colors",
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
  });
});
