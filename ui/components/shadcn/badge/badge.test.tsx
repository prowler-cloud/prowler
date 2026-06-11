import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Badge } from "./badge";

describe("Badge", () => {
  it("renders its children", () => {
    render(<Badge variant="info">Assessment</Badge>);
    expect(screen.getByText("Assessment")).toBeInTheDocument();
  });

  it("applies the info variant token classes", () => {
    const { container } = render(<Badge variant="info">Info</Badge>);
    const badge = container.querySelector("[data-slot='badge']");
    // The info variant is built from the existing design-system blue token
    // (bg-data-info) rather than a bespoke palette.
    expect(badge?.className).toContain("bg-bg-data-info/15");
    expect(badge?.className).toContain("text-bg-data-info");
  });

  it("merges a custom className", () => {
    const { container } = render(
      <Badge variant="tag" className="extra-class">
        Tag
      </Badge>,
    );
    const badge = container.querySelector("[data-slot='badge']");
    expect(badge?.className).toContain("extra-class");
  });
});
