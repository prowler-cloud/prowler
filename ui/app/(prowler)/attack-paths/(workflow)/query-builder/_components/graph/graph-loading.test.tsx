import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphLoading } from "./graph-loading";

describe("GraphLoading", () => {
  it("uses the provider wizard loading pattern", () => {
    render(<GraphLoading />);

    expect(screen.getByTestId("graph-loading")).toHaveClass(
      "flex",
      "min-h-[320px]",
      "items-center",
      "justify-center",
      "gap-4",
      "text-center",
    );
    expect(screen.getByLabelText("Loading")).toHaveClass(
      "size-6",
      "animate-spin",
    );
    expect(screen.getByText("Loading Attack Paths graph...")).toHaveClass(
      "text-muted-foreground",
      "text-sm",
    );
  });
});
