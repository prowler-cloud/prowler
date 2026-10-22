import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Fragment, type ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { resolveFindingIdsByVisibleGroupResources } from "@/actions/findings/findings-by-resource";
import { useCloudUpgradeStore } from "@/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import {
  FINDINGS_ROW_TYPE,
  type FindingGroupRow,
} from "@/types/findings-table";
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
    getRowCanSelect,
    onRowSelectionChange,
    renderAfterRow,
    previewLock,
  }: {
    data?: Array<{ checkId?: string }>;
    toolbarRightContent?: ReactNode;
    getRowAttributes?: (row: {
      index: number;
      original: { checkId?: string };
    }) => Record<string, string | undefined>;
    getRowCanSelect?: (row: {
      index: number;
      original: { checkId?: string };
    }) => boolean;
    previewLock?: { visibleRowCount: number; overlay: ReactNode };
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
      {previewLock && (
        <div
          data-testid="preview-lock"
          data-visible={previewLock.visibleRowCount}
        >
          {previewLock.overlay}
        </div>
      )}
      <table>
        <tbody>
          {(data ?? []).map((original, index) => (
            <Fragment key={original.checkId ?? index}>
              <tr
                data-testid={`row-${index}`}
                data-can-select={String(
                  getRowCanSelect?.({ index, original }) ?? true,
                )}
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

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({
    contributorId,
    item,
  }: {
    contributorId: string;
    item: unknown;
  }) => (
    <output data-testid={`context-${contributorId}`}>
      {JSON.stringify(item)}
    </output>
  ),
}));

vi.mock("@/components/onboarding", () => ({
  // Exposes the "Open a finding group" step so tests can drive it and read
  // whether the handler waited for the resources step.
  OnboardingTrigger: ({
    stepHandlers,
  }: {
    stepHandlers?: Record<
      string,
      {
        onNext?: (context: {
          waitForStep: (target: string) => Promise<void>;
        }) => Promise<void>;
      }
    >;
  }) => (
    <button
      type="button"
      data-testid="onboarding-trigger"
      onClick={() => {
        const waitForStep = vi.fn(async () => {});
        void stepHandlers?.group?.onNext?.({ waitForStep }).then(() => {
          document.body.dataset.tourWaited = String(
            waitForStep.mock.calls.length > 0,
          );
        });
      }}
    >
      Open first group
    </button>
  ),
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

function makeGroup(
  checkId: string,
  resourcesFail = 2,
  overrides: Partial<FindingGroupRow> = {},
): FindingGroupRow {
  return {
    id: `group-${checkId}`,
    rowType: FINDINGS_ROW_TYPE.GROUP,
    checkId,
    checkTitle: `Title ${checkId}`,
    severity: "high",
    status: "FAIL",
    resourcesFail,
    resourcesTotal: Math.max(resourcesFail, 1),
    newCount: 0,
    changedCount: 0,
    mutedCount: 0,
    providers: [],
    updatedAt: "2026-07-27T00:00:00Z",
    ...overrides,
  };
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

  it("publishes the loaded total and selected finding groups as context", async () => {
    // Given
    const user = userEvent.setup();
    const data = [
      makeGroup("check-a", 1, {
        id: "group-1",
        checkTitle: "Public bucket",
        severity: "critical",
      }),
    ];

    render(
      <FindingsGroupTable
        data={data}
        metadata={{
          pagination: { page: 1, pages: 1, count: 12 },
          version: "v1",
        }}
        resolvedFilters={{}}
        hasHistoricalData={false}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Select check-a" }));

    // Then
    expect(screen.getByTestId("context-findings-summary")).toHaveTextContent(
      '"total":12',
    );
    expect(
      await screen.findByTestId("context-finding-group-group-1"),
    ).toHaveTextContent('"checkId":"check-a"');
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

  describe("when the table is locked to a preview", () => {
    const lockedGroups = [
      makeGroup("check-a"),
      makeGroup("check-b"),
      makeGroup("check-c"),
    ];

    beforeEach(() => {
      useCloudUpgradeStore.getState().closeCloudUpgrade();
    });

    it("floats the unlock prompt over the table and keeps locked groups unselectable", () => {
      // Given / When
      render(
        <FindingsGroupTable
          data={lockedGroups}
          metadata={{
            pagination: { page: 1, pages: 1, count: 40 },
            version: "v1",
          }}
          resolvedFilters={{}}
          hasHistoricalData={false}
          previewRowLimit={2}
        />,
      );

      // Then
      expect(screen.getByTestId("preview-lock")).toHaveAttribute(
        "data-visible",
        "2",
      );
      expect(
        screen.getByRole("button", { name: "Unlock All Findings" }),
      ).toBeInTheDocument();
      expect(screen.getByTestId("row-1")).toHaveAttribute(
        "data-can-select",
        "true",
      );
      expect(screen.getByTestId("row-2")).toHaveAttribute(
        "data-can-select",
        "false",
      );
    });

    it("still opens an expanded deep link inside the preview", () => {
      // Given / When
      render(
        <FindingsGroupTable
          data={lockedGroups}
          resolvedFilters={{}}
          hasHistoricalData={false}
          expandedCheckId="check-b"
          previewRowLimit={2}
        />,
      );

      // Then
      expect(
        screen.getByRole("button", { name: "Select finding-1" }),
      ).toBeInTheDocument();
    });

    it("skips the tour resources step when the only drillable group is locked", async () => {
      // Given: the previewed rows cannot drill down, a locked one can
      const user = userEvent.setup();
      delete document.body.dataset.tourWaited;
      render(
        <FindingsGroupTable
          data={[
            makeGroup("check-a", 0, { resourcesTotal: 0 }),
            makeGroup("check-b", 0, { resourcesTotal: 0 }),
            makeGroup("check-c"),
          ]}
          resolvedFilters={{}}
          hasHistoricalData={false}
          previewRowLimit={2}
        />,
      );

      // When
      await user.click(
        screen.getByRole("button", { name: "Open first group" }),
      );

      // Then: no drill-down, no upgrade prompt, and the tour did not wait
      await waitFor(() =>
        expect(document.body.dataset.tourWaited).toBe("false"),
      );
      expect(
        screen.queryByRole("button", { name: "Select finding-1" }),
      ).not.toBeInTheDocument();
      expect(useCloudUpgradeStore.getState().activeFeature).toBeNull();
    });

    it("ignores an expanded deep link that points past the preview", () => {
      // Given / When
      render(
        <FindingsGroupTable
          data={lockedGroups}
          resolvedFilters={{}}
          hasHistoricalData={false}
          expandedCheckId="check-c"
          previewRowLimit={2}
        />,
      );

      // Then
      expect(
        screen.queryByRole("button", { name: "Select finding-1" }),
      ).not.toBeInTheDocument();
    });

    it("answers a drill-down past the preview with the upgrade prompt", async () => {
      // Given
      const user = userEvent.setup();
      render(
        <FindingsGroupTable
          data={lockedGroups}
          resolvedFilters={{}}
          hasHistoricalData={false}
          previewRowLimit={2}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Expand check-c" }));

      // Then
      expect(useCloudUpgradeStore.getState().activeFeature).toBe(
        PAID_PLAN_UPGRADE_FEATURE.FINDINGS_PREVIEW,
      );
      expect(
        screen.queryByRole("button", { name: "Select finding-1" }),
      ).not.toBeInTheDocument();
    });
  });
});
