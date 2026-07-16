import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Fragment, type ReactNode, useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { resolveFindingIdsByVisibleGroupResources } from "@/actions/findings/findings-by-resource";

import { FindingsGroupTable } from "./findings-group-table";

const {
  isGroupedJiraDispatchEnabledMock,
  SendToJiraModalMock,
  setOnDrillDownMock,
  triggerOnDrillDownMock,
} = vi.hoisted(() => {
  let onDrillDown: ((checkId: string, group: unknown) => void) | undefined;

  return {
    isGroupedJiraDispatchEnabledMock: vi.fn(() => false),
    SendToJiraModalMock: vi.fn((_props: unknown) => null),
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
  useRouter: () => ({
    refresh: vi.fn(),
  }),
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
      <span>10 Total Entries</span>
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

vi.mock("@/lib/deployment", () => ({
  isGroupedJiraDispatchEnabled: isGroupedJiraDispatchEnabledMock,
}));

vi.mock("../send-to-jira-modal", () => ({
  SendToJiraModal: SendToJiraModalMock,
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
    columnCount,
    onResourceSelectionChange,
  }: {
    columnCount?: number;
    onResourceSelectionChange?: (selectedResourceIds: string[]) => void;
  }) => (
    <tr>
      <td colSpan={columnCount}>
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

vi.mock("../floating-mute-button", () => ({
  PROWLER_CLOUD_ONLY_TOOLTIP: "Available only in Prowler Cloud",
  FloatingMuteButton: ({
    label,
    muteLabel,
    sendToJiraLabel,
    onBeforeOpen,
    onSendToJira,
    canSendToJira,
    showSendToJira,
    jiraDisabledTooltip,
  }: {
    label?: string;
    muteLabel?: string;
    sendToJiraLabel?: string;
    onBeforeOpen?: () => Promise<string[]>;
    onSendToJira?: () => void;
    canSendToJira?: boolean;
    showSendToJira?: boolean;
    jiraDisabledTooltip?: string;
  }) => {
    const [isChooserOpen, setIsChooserOpen] = useState(false);

    return (
      <div>
        <button type="button" onClick={() => setIsChooserOpen(true)}>
          {label}
        </button>
        {isChooserOpen && (
          <div role="dialog" aria-label="Choose action">
            <button type="button" onClick={() => void onBeforeOpen?.()}>
              {muteLabel ?? "Mute"}
            </button>
            {showSendToJira && (
              <button
                type="button"
                disabled={!canSendToJira}
                title={!canSendToJira ? jiraDisabledTooltip : undefined}
                onClick={onSendToJira}
              >
                {sendToJiraLabel ?? "Send to Jira"}
              </button>
            )}
          </div>
        )}
      </div>
    );
  },
}));

describe("FindingsGroupTable", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    isGroupedJiraDispatchEnabledMock.mockReturnValue(false);
  });

  describe("toolbar", () => {
    it("should render the muted findings checkbox inside the table toolbar", () => {
      // Given
      render(
        <FindingsGroupTable
          data={[]}
          metadata={{
            pagination: {
              page: 1,
              pages: 1,
              count: 10,
            },
            version: "v1",
          }}
          resolvedFilters={{ "filter[muted]": "false" }}
          hasHistoricalData={false}
        />,
      );

      // When
      const toolbar = screen.getByTestId("table-toolbar-right");

      // Then
      expect(
        screen.getByRole("checkbox", { name: "Include muted findings" }),
      ).toBeInTheDocument();
      expect(toolbar).toHaveTextContent("Include muted findings");
    });
  });

  describe("explore-findings tour gating", () => {
    it("does not mount the tour trigger when there are no finding groups", () => {
      // Given an empty table (e.g. a scan is still running)
      render(
        <FindingsGroupTable
          data={[]}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // Then the tour never starts — there is no first-row anchor for the
      // "Open a finding group" step to resolve, which would otherwise throw.
      expect(
        screen.queryByTestId("onboarding-trigger"),
      ).not.toBeInTheDocument();
      // PageReady still signals the navbar that the route's data has loaded.
      expect(screen.getByTestId("page-ready")).toBeInTheDocument();
    });

    it("mounts the tour trigger once at least one finding group exists", () => {
      // Given a populated table
      const data = [{ checkId: "check-a" }] as unknown as Parameters<
        typeof FindingsGroupTable
      >[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // Then the explore-findings tour is allowed to start.
      expect(screen.getByTestId("onboarding-trigger")).toBeInTheDocument();
    });
  });

  describe("onboarding anchor", () => {
    it("anchors the finding-group tour step to the first row only", () => {
      // Given two finding groups (the tour must point at the first, even if there is one)
      const data = [
        { checkId: "check-a" },
        { checkId: "check-b" },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // Then driver.js resolves `[data-tour-id="explore-findings-group"]` to the first row.
      expect(screen.getByTestId("row-0")).toHaveAttribute(
        "data-tour-id",
        "explore-findings-group",
      );
      expect(screen.getByTestId("row-1")).not.toHaveAttribute("data-tour-id");
    });
  });

  describe("expanded deep link", () => {
    it("opens the matching drillable group from expandedCheckId", () => {
      // Given
      const data = [
        { checkId: "check-a", resourcesTotal: 1 },
        { checkId: "check-b", resourcesTotal: 1 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
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

    it("ignores a missing expandedCheckId", () => {
      // Given
      const data = [
        { checkId: "check-a", resourcesTotal: 1 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
          expandedCheckId="check-missing"
        />,
      );

      // Then
      expect(
        screen.queryByRole("button", { name: "Select finding-1" }),
      ).not.toBeInTheDocument();
    });

    it("ignores a non-drillable expandedCheckId", () => {
      // Given
      const data = [
        { checkId: "check-a", resourcesTotal: 0 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
          expandedCheckId="check-a"
        />,
      );

      // Then
      expect(
        screen.queryByRole("button", { name: "Select finding-1" }),
      ).not.toBeInTheDocument();
    });

    it("allows manual collapse after opening from expandedCheckId", async () => {
      // Given
      const user = userEvent.setup();
      const data = [
        { checkId: "check-a", resourcesTotal: 1 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
          expandedCheckId="check-a"
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Expand check-a" }));

      // Then
      expect(
        screen.queryByRole("button", { name: "Select finding-1" }),
      ).not.toBeInTheDocument();
    });

    it("clears the expanded group when expandedCheckId is removed", () => {
      // Given
      const data = [
        { checkId: "check-a", resourcesTotal: 1 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];
      const { rerender } = render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
          expandedCheckId="check-a"
        />,
      );
      expect(
        screen.getByRole("button", { name: "Select finding-1" }),
      ).toBeInTheDocument();

      // When
      rerender(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // Then
      expect(
        screen.queryByRole("button", { name: "Select finding-1" }),
      ).not.toBeInTheDocument();
    });
  });

  describe("bulk Jira action", () => {
    it("should summarize group-only selections", async () => {
      // Given
      const user = userEvent.setup();
      const data = [
        { checkId: "check-a", resourcesFail: 1, resourcesTotal: 1 },
        { checkId: "check-b", resourcesFail: 1, resourcesTotal: 1 },
        { checkId: "check-c", resourcesFail: 1, resourcesTotal: 1 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Select check-a" }));
      await user.click(screen.getByRole("button", { name: "Select check-b" }));
      await user.click(screen.getByRole("button", { name: "Select check-c" }));

      // Then
      expect(
        screen.getByRole("button", { name: "3 Groups selected" }),
      ).toBeInTheDocument();
    });

    it("should summarize selected groups with nested findings", async () => {
      // Given
      const user = userEvent.setup();
      const data = [
        { checkId: "check-a", resourcesFail: 1, resourcesTotal: 1 },
        { checkId: "check-b", resourcesFail: 1, resourcesTotal: 1 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Select check-a" }));
      await user.click(screen.getByRole("button", { name: "Expand check-b" }));
      await user.click(
        screen.getByRole("button", { name: "Select finding-1" }),
      );

      // Then
      expect(
        screen.getByRole("button", {
          name: "1 Group and 1 Finding selected",
        }),
      ).toBeInTheDocument();

      await user.click(
        screen.getByRole("button", {
          name: "1 Group and 1 Finding selected",
        }),
      );
      const actionChooser = screen.getByRole("dialog", {
        name: "Choose action",
      });
      expect(
        within(actionChooser).getByRole("button", {
          name: "Send 1 Group and 1 Finding to Jira",
        }),
      ).toBeInTheDocument();
      expect(
        within(actionChooser).getByRole("button", {
          name: "Mute 1 Group and 1 Finding",
        }),
      ).toBeInTheDocument();
      expect(
        screen.queryByRole("button", { name: "Send 1 Group to Jira" }),
      ).not.toBeInTheDocument();
    });

    it("should pass both group and child finding batches to Jira for mixed selections", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 1,
          resourcesTotal: 1,
        },
        {
          checkId: "check-b",
          checkTitle: "Check B",
          resourcesFail: 1,
          resourcesTotal: 1,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      await user.click(screen.getByRole("button", { name: "Select check-a" }));
      await user.click(screen.getByRole("button", { name: "Expand check-b" }));
      await user.click(
        screen.getByRole("button", { name: "Select finding-1" }),
      );

      // When
      await user.click(
        screen.getByRole("button", {
          name: "1 Group and 1 Finding selected",
        }),
      );
      await user.click(
        screen.getByRole("button", {
          name: "Send 1 Group and 1 Finding to Jira",
        }),
      );

      // Then
      const lastCall = SendToJiraModalMock.mock.calls.at(-1)?.[0];
      expect(lastCall).toMatchObject({
        isOpen: true,
        targetIds: ["check-a"],
        targetType: "check_id",
        targetBatches: [
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
        canChooseGroupedDispatch: false,
        description: "Create Jira issues for 1 Group and 1 Finding.",
      });
    });

    it("should pass both child finding and group batches to Jira when the child finding is selected first", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 1,
          resourcesTotal: 1,
        },
        {
          checkId: "check-b",
          checkTitle: "Check B",
          resourcesFail: 1,
          resourcesTotal: 1,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      await user.click(screen.getByRole("button", { name: "Expand check-a" }));
      await user.click(
        screen.getByRole("button", { name: "Select finding-1" }),
      );
      await user.click(screen.getByRole("button", { name: "Select check-b" }));

      // When
      await user.click(
        screen.getByRole("button", {
          name: "1 Group and 1 Finding selected",
        }),
      );
      await user.click(
        screen.getByRole("button", {
          name: "Send 1 Group and 1 Finding to Jira",
        }),
      );

      // Then
      const lastCall = SendToJiraModalMock.mock.calls.at(-1)?.[0];
      expect(lastCall).toMatchObject({
        isOpen: true,
        targetIds: ["check-b"],
        targetType: "check_id",
        targetBatches: [
          {
            targetIds: ["check-b"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1"],
            targetType: "finding_id",
            dispatchMode: "individual",
          },
        ],
        canChooseGroupedDispatch: false,
        description: "Create Jira issues for 1 Group and 1 Finding.",
      });
    });

    it("should leave multi child Finding dispatch mode to the Jira modal for mixed bulk selections", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 2,
          resourcesTotal: 2,
        },
        {
          checkId: "check-b",
          checkTitle: "Check B",
          resourcesFail: 1,
          resourcesTotal: 1,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      await user.click(screen.getByRole("button", { name: "Expand check-a" }));
      await user.click(
        screen.getByRole("button", { name: "Select findings 1 and 2" }),
      );
      await user.click(screen.getByRole("button", { name: "Select check-b" }));

      // When
      await user.click(
        screen.getByRole("button", {
          name: "1 Group and 2 Findings selected",
        }),
      );
      await user.click(
        screen.getByRole("button", {
          name: "Send 1 Group and 2 Findings to Jira",
        }),
      );

      // Then
      const lastCall = SendToJiraModalMock.mock.calls.at(-1)?.[0] as {
        targetBatches: Array<Record<string, unknown>>;
      };
      expect(lastCall).toMatchObject({
        isOpen: true,
        targetIds: ["check-b"],
        targetType: "check_id",
        targetBatches: [
          {
            targetIds: ["check-b"],
            targetType: "check_id",
            dispatchMode: "grouped",
          },
          {
            targetIds: ["finding-1", "finding-2"],
            targetType: "finding_id",
          },
        ],
        canChooseGroupedDispatch: false,
        description: "Create Jira issues for 1 Group and 2 Findings.",
      });
      expect(lastCall.targetBatches[1]).not.toHaveProperty("dispatchMode");
    });

    it("should route choosing Mute through the existing mute resolver", async () => {
      // Given
      const user = userEvent.setup();
      vi.mocked(resolveFindingIdsByVisibleGroupResources).mockResolvedValue([
        "finding-a",
      ]);
      const data = [
        { checkId: "check-a", resourcesFail: 1, resourcesTotal: 1 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Select check-a" }));
      await user.click(
        screen.getByRole("button", { name: "1 Group selected" }),
      );
      await user.click(
        within(screen.getByRole("dialog", { name: "Choose action" })).getByRole(
          "button",
          { name: "Mute 1 Group" },
        ),
      );

      // Then
      expect(resolveFindingIdsByVisibleGroupResources).toHaveBeenCalledWith({
        checkId: "check-a",
        filters: {},
        hasDateOrScanFilter: false,
        resourceSearch: undefined,
      });
    });

    it("should clear nested selections when expanding another group and preserve selected groups", async () => {
      // Given
      const user = userEvent.setup();
      const data = [
        { checkId: "check-a", resourcesFail: 1, resourcesTotal: 1 },
        { checkId: "check-b", resourcesFail: 1, resourcesTotal: 1 },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Select check-b" }));
      await user.click(screen.getByRole("button", { name: "Expand check-a" }));
      await user.click(
        screen.getByRole("button", { name: "Select finding-1" }),
      );

      // Then nested and group selections are both visible/actionable.
      expect(
        screen.getByRole("button", {
          name: "1 Group and 1 Finding selected",
        }),
      ).toBeInTheDocument();

      // When switching groups, nested selection clears while the selected group remains.
      await user.click(screen.getByRole("button", { name: "Expand check-b" }));

      // Then
      expect(
        screen.queryByRole("button", {
          name: "1 Group and 1 Finding selected",
        }),
      ).not.toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "1 Group selected" }),
      ).toBeInTheDocument();
    });

    it("should open Jira modal for resource-only selections", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 1,
          resourcesTotal: 1,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Expand check-a" }));
      await user.click(
        screen.getByRole("button", { name: "Select finding-1" }),
      );

      // Then
      expect(
        screen.getByRole("button", { name: "1 Finding selected" }),
      ).toBeInTheDocument();
      await user.click(
        screen.getByRole("button", { name: "1 Finding selected" }),
      );
      await user.click(
        screen.getByRole("button", { name: "Send 1 Finding to Jira" }),
      );

      const lastCall = SendToJiraModalMock.mock.calls.at(-1)?.[0];
      expect(lastCall).toMatchObject({
        isOpen: true,
        targetIds: ["finding-1"],
        targetType: "finding_id",
        defaultDispatchMode: "individual",
        canChooseGroupedDispatch: false,
      });
    });

    it("should allow grouped Jira dispatch choice for multiple selected resources in one finding group", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 2,
          resourcesTotal: 2,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
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
      await user.click(
        screen.getByRole("button", { name: "2 Findings selected" }),
      );
      await user.click(
        screen.getByRole("button", { name: "Send 2 Findings to Jira" }),
      );

      const lastCall = SendToJiraModalMock.mock.calls.at(-1)?.[0];
      expect(lastCall).toMatchObject({
        isOpen: true,
        targetIds: ["finding-1", "finding-2"],
        targetType: "finding_id",
        defaultDispatchMode: "grouped",
        canChooseGroupedDispatch: true,
      });
    });

    it("should disable selected multi-finding Jira dispatch when grouped dispatch is disabled", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(false);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 2,
          resourcesTotal: 2,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Expand check-a" }));
      await user.click(
        screen.getByRole("button", { name: "Select findings 1 and 2" }),
      );
      await user.click(
        screen.getByRole("button", { name: "2 Findings selected" }),
      );
      const jiraButton = screen.getByRole("button", {
        name: "Send 2 Findings to Jira",
      });
      await user.click(jiraButton);

      // Then
      expect(jiraButton).toBeDisabled();
      expect(jiraButton).toHaveAttribute(
        "title",
        "Available only in Prowler Cloud",
      );
      expect(SendToJiraModalMock).not.toHaveBeenCalledWith(
        expect.objectContaining({ isOpen: true }),
        undefined,
      );
    });

    it("should render disabled Cloud-only bulk Jira button when grouped Jira dispatch is disabled", async () => {
      // Given
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          resourcesFail: 1,
          resourcesTotal: 1,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Select check-a" }));
      await user.click(
        screen.getByRole("button", { name: "1 Group selected" }),
      );

      // Then
      const jiraButton = screen.getByRole("button", {
        name: "Send 1 Group to Jira",
      });
      expect(jiraButton).toBeVisible();
      expect(jiraButton).toBeDisabled();
      expect(jiraButton).toHaveAttribute(
        "title",
        "Available only in Prowler Cloud",
      );
      expect(
        screen.getByRole("button", { name: "Mute 1 Group" }),
      ).toBeInTheDocument();
      expect(SendToJiraModalMock).not.toHaveBeenCalledWith(
        expect.objectContaining({ isOpen: true }),
        undefined,
      );
    });

    it("should allow grouped Jira dispatch choice for one selected finding group with multiple failing resources", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 2,
          resourcesTotal: 2,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      await user.click(screen.getByRole("button", { name: "Select check-a" }));

      // When
      await user.click(
        screen.getByRole("button", { name: "1 Group selected" }),
      );
      await user.click(
        screen.getByRole("button", { name: "Send 1 Group to Jira" }),
      );

      // Then
      const lastCall = SendToJiraModalMock.mock.calls.at(-1)?.[0];
      expect(lastCall).toMatchObject({
        isOpen: true,
        targetIds: ["check-a"],
        targetType: "check_id",
        defaultDispatchMode: "grouped",
        canChooseGroupedDispatch: true,
        selectedResourceCount: 2,
      });
    });

    it("should not require grouped Jira dispatch choice for one selected finding group with one failing resource", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 1,
          resourcesTotal: 1,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      await user.click(screen.getByRole("button", { name: "Select check-a" }));

      // When
      await user.click(
        screen.getByRole("button", { name: "1 Group selected" }),
      );
      await user.click(
        screen.getByRole("button", { name: "Send 1 Group to Jira" }),
      );

      // Then
      const lastCall = SendToJiraModalMock.mock.calls.at(-1)?.[0];
      expect(lastCall).toMatchObject({
        isOpen: true,
        targetIds: ["check-a"],
        targetType: "check_id",
        defaultDispatchMode: "grouped",
        canChooseGroupedDispatch: false,
        selectedResourceCount: 1,
      });
    });

    it("should use grouped dispatch mode for multiple selected finding groups", async () => {
      // Given
      isGroupedJiraDispatchEnabledMock.mockReturnValue(true);
      const user = userEvent.setup();
      const data = [
        {
          checkId: "check-a",
          checkTitle: "Check A",
          resourcesFail: 2,
          resourcesTotal: 2,
        },
        {
          checkId: "check-b",
          checkTitle: "Check B",
          resourcesFail: 3,
          resourcesTotal: 3,
        },
      ] as unknown as Parameters<typeof FindingsGroupTable>[0]["data"];

      render(
        <FindingsGroupTable
          data={data}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      await user.click(screen.getByRole("button", { name: "Select check-a" }));
      await user.click(screen.getByRole("button", { name: "Select check-b" }));

      // When
      await user.click(
        screen.getByRole("button", { name: "2 Groups selected" }),
      );
      await user.click(
        screen.getByRole("button", { name: "Send 2 Groups to Jira" }),
      );

      // Then
      const lastCall = SendToJiraModalMock.mock.calls.at(-1)?.[0];
      expect(lastCall).toMatchObject({
        isOpen: true,
        targetIds: ["check-a", "check-b"],
        targetType: "check_id",
        defaultDispatchMode: "grouped",
        canChooseGroupedDispatch: false,
        selectedResourceCount: 2,
      });
    });
  });
});
