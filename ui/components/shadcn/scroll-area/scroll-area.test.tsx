import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScrollArea } from "./scroll-area";

describe("ScrollArea", () => {
  it("provides a medium viewport height", () => {
    render(<ScrollArea size="md">Content</ScrollArea>);

    expect(
      screen.getByText("Content").parentElement?.parentElement,
    ).toHaveClass("h-72");
  });
});
