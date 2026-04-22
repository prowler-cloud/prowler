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
  it("renders the table skeleton with the new header, toolbar, rows, and 7 columns", () => {
    render(<MuteRulesTableSkeleton />);

    const skeleton = screen.getByTestId("mute-rules-table-skeleton");
    const intro = screen.getByTestId("mute-rules-table-skeleton-intro");

    expect(skeleton).toHaveClass(
      "bg-bg-neutral-secondary",
      "border-border-neutral-secondary",
      "rounded-large",
    );
    // Intro: title + 1 description line
    expect(intro.querySelectorAll("[data-slot='skeleton']").length).toBe(2);
    expect(skeleton.querySelector("table")).toBeInTheDocument();
    // 7 columns: select + name + reason + findings + created + enabled + actions
    expect(skeleton.querySelectorAll("thead th").length).toBe(7);
    expect(skeleton.querySelectorAll("tbody tr").length).toBeGreaterThanOrEqual(
      8,
    );
  });
});
