import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Tooltip, TooltipContent, TooltipTrigger } from "./tooltip";

describe("TooltipContent", () => {
  it("uses a constrained content width through its semantic API", async () => {
    // Given / When
    render(
      <Tooltip defaultOpen>
        <TooltipTrigger>Finding</TooltipTrigger>
        <TooltipContent maxWidth="md">Long finding description</TooltipContent>
      </Tooltip>,
    );

    // Then
    const content = (
      await screen.findAllByText("Long finding description")
    ).find((element) => element.dataset.slot === "tooltip-content");
    expect(content).toHaveClass("max-w-96");
  });
});
