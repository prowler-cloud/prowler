import type { CellContext } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { createMuteRulesColumns } from "./mute-rules-columns";

vi.mock("@/components/ui/entities", () => ({
  DateWithTime: () => null,
}));

vi.mock("@/components/ui/table", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("./mute-rule-enabled-toggle", () => ({
  MuteRuleEnabledToggle: () => null,
}));

vi.mock("./mute-rule-row-actions", () => ({
  MuteRuleRowActions: () => null,
}));

vi.mock("@/components/shadcn", async () => {
  const actual = await vi.importActual<Record<string, unknown>>(
    "@/components/shadcn",
  );
  return {
    ...actual,
    Checkbox: () => null,
  };
});

describe("createMuteRulesColumns", () => {
  it("renders a compact actionable summary that opens the full list via callback", async () => {
    const onViewTargets = vi.fn();
    const columns = createMuteRulesColumns(vi.fn(), vi.fn(), onViewTargets);
    const findingsColumn = columns.find(
      (column) =>
        "accessorKey" in column && column.accessorKey === "finding_count",
    );
    if (!findingsColumn) throw new Error("finding_count column not found");

    const row = {
      original: {
        type: "mute-rules" as const,
        id: "mute-rule-1",
        attributes: {
          inserted_at: "2026-04-22T09:00:00Z",
          updated_at: "2026-04-22T09:05:00Z",
          name: "Ignore dev bucket",
          reason: "Existing reason",
          enabled: true,
          finding_uids: ["uid-1", "uid-2", "uid-3"],
        },
        targetLabels: [
          "S3 Bucket Public Access • bucket-a",
          "EC2 Public IP • instance-a",
          "uid-3",
        ],
        targetSummaryLabel: "S3 Bucket Public Access • bucket-a",
        hiddenTargetCount: 2,
      },
    };

    const findingsCell = findingsColumn.cell as (
      context: CellContext<(typeof row)["original"], unknown>,
    ) => React.ReactNode;

    render(<>{findingsCell({ row } as never)}</>);

    const button = screen.getByRole("button", {
      name: "View muted findings for Ignore dev bucket",
    });

    expect(
      screen.getByText("S3 Bucket Public Access • bucket-a"),
    ).toBeInTheDocument();
    expect(screen.getByText("+2 more")).toBeInTheDocument();

    button.click();
    expect(onViewTargets).toHaveBeenCalledWith(row.original);
  });
});
