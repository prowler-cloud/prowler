import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Fragment, type ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { resolveFindingIdsByVisibleGroupResources } from "@/actions/findings/findings-by-resource";
import type { JiraDispatchModalPayload } from "@/types/jira-dispatch";

import { FindingsGroupTable } from "./findings-group-table";

const {
  FloatingSelectionActionsMock,
  setOnDrillDownMock,
  triggerOnDrillDownMock,
} = vi.hoisted(() => {
  let onDrillDown: ((checkId: string, group: unknown) => void) | undefined;

  return {
    FloatingSelectionActionsMock: vi.fn((_props: unknown) => null),
    setOnDrillDownMock: vi.fn(
      (handler: ((checkId: string, group: unknown) => void) | undefined) => {
        onDrillDown = handler;
      },
    ),
    triggerOnDrillDownMock: vi.fn((checkId: string, group: unknown) => {
      onDrillDown?.(checkId, group);
    }),
  };
});

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => "/findings",
}));

vi.mock("@/components/shadcn/table", () => ({
  DataTable: ({
    data,
    toolbarRightContent,
    getRowAttributes,
    onRowSelectionChange,
    renderAfterRow,
  }: {
    data?: Array<{ checkId?: string }>;
    toolbarRightContent?: ReactNode;
    getRowAttributes?: (row: {
      index: number;
      original: { checkId?: string };
    }) => Record<string, string | undefined>;
    onRowSelectionChange?: (
      updater: (previous: Record<string, boolean>) => Record<string, boolean>,
    ) => void;
    renderAfterRow?: (row: {
      index: number;
      original: { checkId?: string };
    }) => ReactNode;
  }) => (
    <div>
      <div data-testid="table-toolbar-right">{toolbarRightContent}</div>
      <table>
        <tbody>
          {(data ?? []).map((original, index) => (
            <Fragment key={original.checkId ?? index}>
              <tr
                data-testid={`row-${index}`}
                {...getRowAttributes?.({ index, original })}
              >
                <td>{original.checkId}</td>
                <td>
                  <button
                    type="button"
                    onClick={() =>
                      onRowSelectionChange?.((previous) => ({
                        ...previous,
                        [index]: true,
                      }))
                    }
                  >
                    Select {original.checkId}
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      triggerOnDrillDownMock(original.checkId ?? "", original)
                    }
                  >
                    Expand {original.checkId}
                  </button>
                </td>
              </tr>
              {renderAfterRow?.({ index, original })}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  ),
}));

vi.mock("@/components/onboarding", () => ({
  OnboardingTrigger: () => <div data-testid="onboarding-trigger" />,
  PageReady: () => <div data-testid="page-ready" />,
}));

vi.mock("@/components/filters/custom-checkbox-muted-findings", () => ({
  CustomCheckboxMutedFindings: () => (
    <label>
      <input type="checkbox" aria-label="Include muted findings" />
      Include muted findings
    </label>
  ),
}));

vi.mock("@/actions/findings/findings-by-resource", () => ({
  resolveFindingIdsByVisibleGroupResources: vi.fn(),
}));

vi.mock("./column-finding-groups", () => ({
  getColumnFindingGroups: ({
    onDrillDown,
  }: {
    onDrillDown?: (checkId: string, group: unknown) => void;
  }) => {
    setOnDrillDownMock(onDrillDown);
    return [];
  },
}));

vi.mock("./inline-resource-container", () => ({
  InlineResourceContainer: ({
    onResourceSelectionChange,
  }: {
    onResourceSelectionChange?: (selectedResourceIds: string[]) => void;
  }) => (
    <tr>
      <td>
        <button
          type="button"
          onClick={() => onResourceSelectionChange?.(["finding-1"])}
        >
          Select finding-1
        </button>
        <button
          type="button"
          onClick={() =>
            onResourceSelectionChange?.(["finding-1", "finding-2"])
          }
        >
          Select findings 1 and 2
        </button>
      </td>
    </tr>
  ),
}));

vi.mock("../floating-selection-actions", () => ({
  FloatingSelectionActions: FloatingSelectionActionsMock,
}));

function makeGroup(checkId: string, resourcesFail = 2) {
  return {
    checkId,
    checkTitle: `Title ${checkId}`,
    resourcesFail,
    resourcesTotal: Math.max(resourcesFail, 1),
    mutedCount: 0,
  } as unknown as Parameters<typeof FindingsGroupTable>[0]["data"][number];
}

function getLastFloatingActionsProps(): {
  jiraPayload: JiraDispatchModalPayload;
  onBeforeOpen: () => Promise<string[]>;
} {
  const props = FloatingSelectionActionsMock.mock.calls.at(-1)?.[0];
  expect(props).toBeDefined();
  return props as unknown as {
    jiraPayload: JiraDispatchModalPayload;
    onBeforeOpen: () => Promise<string[]>;
  };
}

describe("FindingsGroupTable", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the muted findings filter in the table toolbar", () => {
    // Given / When
    render(
      <FindingsGroupTable
        data={[]}
        resolvedFilters={{}}
        hasHistoricalData={false}
      />,
    );

    // Then
    expect(
      screen.getByRole("checkbox", { name: "Include muted findings" }),
    ).toBeInTheDocument();
  });

  it("mounts the tour only when finding groups exist", () => {
    // Given / When
    const { rerender } = render(
      <FindingsGroupTable
        data={[]}
        resolvedFilters={{}}
        hasHistoricalData={false}
      />,
    );

    // Then
    expect(screen.queryByTestId("onboarding-trigger")).not.toBeInTheDocument();
    expect(screen.getByTestId("page-ready")).toBeInTheDocument();

    // When
    rerender(
      <FindingsGroupTable
        data={[makeGroup("check-a")]}
        resolvedFilters={{}}
        hasHistoricalData={false}
      />,
    );

    // Then
    expect(screen.getByTestId("onboarding-trigger")).toBeInTheDocument();
  });

  it("anchors the finding-group tour to the first row only", () => {
    // Given / When
    render(
      <FindingsGroupTable
        data={[makeGroup("check-a"), makeGroup("check-b")]}
        resolvedFilters={{}}
        hasHistoricalData={false}
      />,
    );

    // Then
    expect(screen.getByTestId("row-0")).toHaveAttribute(
      "data-tour-id",
      "explore-findings-group",
    );
    expect(screen.getByTestId("row-1")).not.toHaveAttribute("data-tour-id");
  });

  it("opens a drillable group from the expanded deep link", () => {
    // Given / When
    render(
      <FindingsGroupTable
        data={[makeGroup("check-a"), makeGroup("check-b")]}
        resolvedFilters={{}}
        hasHistoricalData={false}
        expandedCheckId="check-b"
      />,
    );

    // Then
    expect(
      screen.getByRole("button", { name: "Select finding-1" }),
    ).toBeInTheDocument();
  });

  it("builds separate Jira batches for selected groups and child findings", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingsGroupTable
        data={[makeGroup("check-a"), makeGroup("check-b")]}
        resolvedFilters={{}}
        hasHistoricalData={false}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Select check-a" }));
    await user.click(screen.getByRole("button", { name: "Expand check-b" }));
    await user.click(screen.getByRole("button", { name: "Select finding-1" }));

    // Then
    expect(getLastFloatingActionsProps().jiraPayload.selection).toEqual({
      kind: "batches",
      batches: [
        {
          targetIds: ["check-a"],
          targetType: "check_id",
          dispatchMode: "grouped",
        },
        {
          targetIds: ["finding-1"],
          targetType: "finding_id",
          dispatchMode: "individual",
        },
      ],
    });
  });

  it("keeps resource-only Jira selections scoped to the expanded group", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <FindingsGroupTable
        data={[makeGroup("check-a")]}
        resolvedFilters={{}}
        hasHistoricalData={false}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Expand check-a" }));
    await user.click(
      screen.getByRole("button", { name: "Select findings 1 and 2" }),
    );

    // Then
    expect(getLastFloatingActionsProps().jiraPayload).toMatchObject({
      selection: {
        kind: "target-list",
        targetIds: ["finding-1", "finding-2"],
        targetType: "finding_id",
      },
      findingTitle: "Title check-a",
      isFindingGroupSelection: true,
      selectedResourceCount: 2,
    });
  });

  it("resolves group selections through the visible-resource query before muting", async () => {
    // Given
    vi.mocked(resolveFindingIdsByVisibleGroupResources).mockResolvedValue([
      "finding-a",
      "finding-b",
    ]);
    const user = userEvent.setup();
    render(
      <FindingsGroupTable
        data={[makeGroup("check-a")]}
        resolvedFilters={{ "filter[severity]": "high" }}
        hasHistoricalData={false}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Select check-a" }));
    const resolvedIds = await getLastFloatingActionsProps().onBeforeOpen();

    // Then
    expect(resolvedIds).toEqual(["finding-a", "finding-b"]);
    expect(resolveFindingIdsByVisibleGroupResources).toHaveBeenCalledWith({
      checkId: "check-a",
      filters: { "filter[severity]": "high" },
      hasDateOrScanFilter: false,
      resourceSearch: undefined,
    });
  });
});
