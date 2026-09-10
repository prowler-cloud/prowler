import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Combobox } from "./combobox";

describe("Combobox", () => {
  it("uses the compact trigger size through its semantic API", () => {
    // Given / When
    render(
      <Combobox
        aria-label="Model"
        size="sm"
        options={[{ value: "gpt-5", label: "GPT-5" }]}
      />,
    );

    // Then
    expect(screen.getByRole("combobox", { name: "Model" })).toHaveClass("h-8");
  });
});
