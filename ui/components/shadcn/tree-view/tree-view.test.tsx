import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { TreeView } from "./tree-view";

const treeData = [
  {
    id: "org-1",
    name: "Organization",
    children: [
      { id: "account-1", name: "Production" },
      { id: "account-2", name: "Development" },
    ],
  },
];

describe("TreeView", () => {
  it("animates node affordances and expanded content", () => {
    // Given
    render(<TreeView data={treeData} expandedIds={["org-1"]} showCheckboxes />);

    // When
    const node = screen.getByRole("treeitem", { name: /organization/i });
    const expandButton = screen.getByRole("button", { name: /collapse/i });
    const chevron = expandButton.querySelector("svg");
    const group = screen.getByRole("group");

    // Then
    expect(node).toHaveClass(
      "transition-[background-color,box-shadow,color]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(expandButton).toHaveClass(
      "transition-colors",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
    expect(chevron).toHaveClass(
      "transition-transform",
      "duration-200",
      "ease-out",
      "motion-reduce:transition-none",
      "rotate-90",
    );
    expect(group).toHaveClass("overflow-hidden");
  });

  it("animates selected leaf row feedback", () => {
    // Given
    render(
      <TreeView
        data={treeData}
        expandedIds={["org-1"]}
        selectedIds={["account-1"]}
        onSelectionChange={vi.fn()}
        showCheckboxes
      />,
    );

    // When
    const selectedLeaf = screen.getByRole("treeitem", { name: /production/i });

    // Then
    expect(selectedLeaf).toHaveAttribute("aria-selected", "true");
    expect(selectedLeaf).toHaveClass(
      "bg-prowler-white/5",
      "transition-[background-color,box-shadow,color]",
      "duration-150",
      "ease-out",
      "motion-reduce:transition-none",
    );
  });
});
