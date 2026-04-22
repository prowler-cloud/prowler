import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/actions/mute-rules", () => ({
  getMuteRules: vi.fn(),
}));

vi.mock("./mute-rule-target-previews", () => ({
  hydrateMuteRuleTargetPreviews: vi.fn(),
}));

vi.mock("./mute-rules-table-client", () => ({
  MuteRulesTableClient: () => null,
}));

import { MuteRulesTableSkeleton } from "./mute-rules-table";

describe("MuteRulesTableSkeleton", () => {
  it("renders a card-like table skeleton with toolbar, rows and pagination", () => {
    render(<MuteRulesTableSkeleton />);

    const skeleton = screen.getByTestId("mute-rules-table-skeleton");
    const intro = screen.getByTestId("mute-rules-table-skeleton-intro");

    expect(skeleton).toHaveClass(
      "bg-bg-neutral-secondary",
      "border-border-neutral-secondary",
      "rounded-large",
    );
    expect(intro.querySelectorAll("[data-slot='skeleton']").length).toBe(4);
    expect(skeleton.querySelector("table")).toBeInTheDocument();
    expect(skeleton.querySelectorAll("tbody tr").length).toBeGreaterThanOrEqual(
      8,
    );
  });
});
