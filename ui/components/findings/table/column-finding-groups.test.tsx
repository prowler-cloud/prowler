import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { InputHTMLAttributes, ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoist mocks for dependencies
// ---------------------------------------------------------------------------

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
  useRouter: () => ({ refresh: vi.fn() }),
  usePathname: () => "/findings",
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/shadcn", () => ({
  Checkbox: ({
    "aria-label": ariaLabel,
    ...props
  }: InputHTMLAttributes<HTMLInputElement> & {
    "aria-label"?: string;
    size?: string;
  }) => <input type="checkbox" aria-label={ariaLabel} {...props} />,
}));

vi.mock("@/components/ui/table", () => ({
  DataTableColumnHeader: ({
    title,
  }: {
    column: unknown;
    title: string;
    param?: string;
  }) => <span>{title}</span>,
  SeverityBadge: ({ severity }: { severity: string }) => (
    <span>{severity}</span>
  ),
  StatusFindingBadge: ({ status }: { status: string }) => <span>{status}</span>,
}));

vi.mock("@/lib", () => ({
  cn: (...args: (string | undefined | false | null)[]) =>
    args.filter(Boolean).join(" "),
}));

vi.mock("./data-table-row-actions", () => ({
  DataTableRowActions: () => null,
}));

vi.mock("./impacted-providers-cell", () => ({
  ImpactedProvidersCell: () => null,
}));

vi.mock("./impacted-resources-cell", () => ({
  ImpactedResourcesCell: ({
    impacted,
    total,
  }: {
    impacted: number;
    total: number;
  }) => <span>{`${impacted}/${total}`}</span>,
}));

vi.mock("./notification-indicator", () => ({
  DeltaValues: { NEW: "new", CHANGED: "changed", NONE: "none" },
  NotificationIndicator: () => null,
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import type { FindingGroupRow } from "@/types";

import { getColumnFindingGroups } from "./column-finding-groups";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeGroup(overrides?: Partial<FindingGroupRow>): FindingGroupRow {
  return {
    id: "group-1",
    rowType: "group" as const,
    checkId: "s3_check",
    checkTitle: "S3 Bucket Public Access",
    severity: "critical",
    status: "FAIL",
    resourcesTotal: 5,
    resourcesFail: 3,
    newCount: 0,
    changedCount: 0,
    mutedCount: 0,
    providers: ["aws"],
    updatedAt: "2024-01-01T00:00:00Z",
    ...overrides,
  } as FindingGroupRow;
}

function renderFindingCell(
  checkTitle: string,
  onDrillDown: (checkId: string, group: FindingGroupRow) => void,
  overrides?: Partial<FindingGroupRow>,
) {
  const columns = getColumnFindingGroups({
    rowSelection: {},
    selectableRowCount: 1,
    onDrillDown,
  });

  // Find the "finding" column (index 2 — the title column)
  const findingColumn = columns.find(
    (col) => (col as { accessorKey?: string }).accessorKey === "finding",
  );
  if (!findingColumn?.cell) throw new Error("finding column not found");

  const group = makeGroup({ checkTitle, ...overrides });
  // Render the cell directly with a minimal row mock
  const CellComponent = findingColumn.cell as (props: {
    row: { original: FindingGroupRow };
  }) => ReactNode;

  render(<div>{CellComponent({ row: { original: group } })}</div>);
}

function renderImpactedResourcesCell(overrides?: Partial<FindingGroupRow>) {
  const columns = getColumnFindingGroups({
    rowSelection: {},
    selectableRowCount: 1,
    onDrillDown: vi.fn(),
  });

  const impactedResourcesColumn = columns.find(
    (col) => (col as { id?: string }).id === "impactedResources",
  );
  if (!impactedResourcesColumn?.cell) {
    throw new Error("impactedResources column not found");
  }

  const group = makeGroup(overrides);
  const CellComponent = impactedResourcesColumn.cell as (props: {
    row: { original: FindingGroupRow };
  }) => ReactNode;

  render(<div>{CellComponent({ row: { original: group } })}</div>);
}

// ---------------------------------------------------------------------------
// Fix 5: Accessibility — <p onClick> → <button>
// ---------------------------------------------------------------------------

describe("column-finding-groups — accessibility of check title cell", () => {
  it("should render the check title as a button element (not a <p>)", () => {
    // Given
    const onDrillDown =
      vi.fn<(checkId: string, group: FindingGroupRow) => void>();

    // When
    renderFindingCell("S3 Bucket Public Access", onDrillDown);

    // Then — there should be a button with the check title text
    const button = screen.getByRole("button", {
      name: "S3 Bucket Public Access",
    });
    expect(button).toBeInTheDocument();
    expect(button.tagName.toLowerCase()).toBe("button");
  });

  it("should NOT render the check title as a <p> element", () => {
    // Given
    const onDrillDown =
      vi.fn<(checkId: string, group: FindingGroupRow) => void>();

    // When
    renderFindingCell("S3 Bucket Public Access", onDrillDown);

    // Then — <p> should not exist as the interactive element
    const paragraphs = document.querySelectorAll("p");
    const clickableParagraph = Array.from(paragraphs).find(
      (p) => p.textContent === "S3 Bucket Public Access",
    );
    expect(clickableParagraph).toBeUndefined();
  });

  it("should call onDrillDown when the button is clicked", async () => {
    // Given
    const onDrillDown =
      vi.fn<(checkId: string, group: FindingGroupRow) => void>();
    const user = userEvent.setup();

    renderFindingCell("S3 Bucket Public Access", onDrillDown);

    // When
    const button = screen.getByRole("button", {
      name: "S3 Bucket Public Access",
    });
    await user.click(button);

    // Then
    expect(onDrillDown).toHaveBeenCalledTimes(1);
    expect(onDrillDown).toHaveBeenCalledWith(
      "s3_check",
      expect.objectContaining({ checkId: "s3_check" }),
    );
  });

  it("should call onDrillDown when Enter key is pressed on the button", async () => {
    // Given
    const onDrillDown =
      vi.fn<(checkId: string, group: FindingGroupRow) => void>();
    const user = userEvent.setup();

    renderFindingCell("My Check Title", onDrillDown);

    // When — tab to button and press Enter
    const button = screen.getByRole("button", { name: "My Check Title" });
    button.focus();
    await user.keyboard("{Enter}");

    // Then — native button handles Enter natively
    expect(onDrillDown).toHaveBeenCalledTimes(1);
  });

  it("should allow expanding a group that only has PASS resources", async () => {
    // Given
    const user = userEvent.setup();
    const onDrillDown =
      vi.fn<(checkId: string, group: FindingGroupRow) => void>();

    renderFindingCell("My Passing Check", onDrillDown, {
      resourcesTotal: 2,
      resourcesFail: 0,
      status: "PASS",
    });

    // When
    await user.click(
      screen.getByRole("button", {
        name: "My Passing Check",
      }),
    );

    // Then
    expect(onDrillDown).toHaveBeenCalledTimes(1);
    expect(onDrillDown).toHaveBeenCalledWith(
      "s3_check",
      expect.objectContaining({
        resourcesTotal: 2,
        resourcesFail: 0,
        status: "PASS",
      }),
    );
  });
});

describe("column-finding-groups — impacted resources count", () => {
  it("should keep impacted resources based on failing resources only", () => {
    // Given/When
    renderImpactedResourcesCell({
      resourcesTotal: 5,
      resourcesFail: 3,
    });

    // Then
    expect(screen.getByText("3/5")).toBeInTheDocument();
  });
});
