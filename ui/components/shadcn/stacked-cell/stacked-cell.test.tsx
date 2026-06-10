import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StackedCell } from "./stacked-cell";

describe("StackedCell", () => {
  it("renders primary and secondary lines", () => {
    render(<StackedCell primary="Jun 15, 2026" secondary="12:00AM MAD" />);

    expect(screen.getByText("Jun 15, 2026")).toBeInTheDocument();
    expect(screen.getByText("12:00AM MAD")).toBeInTheDocument();
  });

  it("omits the secondary line when not provided", () => {
    const { container } = render(<StackedCell primary="Manual" />);

    expect(screen.getByText("Manual")).toBeInTheDocument();
    expect(container.querySelectorAll("span")).toHaveLength(1);
  });
});
