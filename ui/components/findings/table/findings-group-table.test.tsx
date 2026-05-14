import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { type ReactNode, useContext } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FindingGroupRow } from "@/types";

import { FindingsGroupTable } from "./findings-group-table";
import { FindingsSelectionContext } from "./findings-selection-context";

const STORAGE_KEY = "prowler:optimistic-muted-groups";

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: vi.fn(),
  }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/ui/table", () => ({
  DataTable: ({
    data,
    toolbarRightContent,
  }: {
    data?: FindingGroupRow[];
    toolbarRightContent?: ReactNode;
  }) => {
    const ctx = useContext(FindingsSelectionContext);
    const rows = data ?? [];
    return (
      <div>
        <div data-testid="table-toolbar-right">{toolbarRightContent}</div>
        <span data-testid="row-count">{rows.length}</span>
        <ul data-testid="visible-groups">
          {rows.map((row) => (
            <li key={row.checkId}>{row.checkId}</li>
          ))}
        </ul>
        <button
          type="button"
          onClick={() => ctx.onMuteComplete?.([rows[0]?.checkId ?? ""])}
        >
          mute-first-row
        </button>
        <button type="button" onClick={() => ctx.onMuteComplete?.()}>
          mute-without-ids
        </button>
        <span>10 Total Entries</span>
      </div>
    );
  },
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
  getColumnFindingGroups: () => [],
}));

vi.mock("./inline-resource-container", () => ({
  InlineResourceContainer: () => null,
}));

vi.mock("../floating-mute-button", () => ({
  FloatingMuteButton: () => null,
}));

const buildGroup = (
  checkId: string,
  overrides: Partial<FindingGroupRow> = {},
): FindingGroupRow =>
  ({
    id: checkId,
    rowType: "group",
    checkId,
    checkTitle: `Title ${checkId}`,
    severity: "high",
    status: "FAIL",
    muted: false,
    resourcesTotal: 10,
    resourcesFail: 5,
    mutedCount: 0,
    newCount: 0,
    changedCount: 0,
    providers: [],
    updatedAt: "2026-04-01T00:00:00Z",
    ...overrides,
  }) as FindingGroupRow;

describe("FindingsGroupTable", () => {
  afterEach(() => {
    sessionStorage.clear();
  });

  describe("toolbar", () => {
    it("should render the muted findings checkbox inside the table toolbar", () => {
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

      const toolbar = screen.getByTestId("table-toolbar-right");

      expect(
        screen.getByRole("checkbox", { name: "Include muted findings" }),
      ).toBeInTheDocument();
      expect(toolbar).toHaveTextContent("Include muted findings");
    });
  });

  describe("optimistic mute via context onMuteComplete", () => {
    it("hides muted groups from the table immediately and persists them in sessionStorage", async () => {
      const user = userEvent.setup();
      render(
        <FindingsGroupTable
          data={[
            buildGroup("group-a"),
            buildGroup("group-b"),
            buildGroup("group-c"),
          ]}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      expect(screen.getByTestId("row-count")).toHaveTextContent("3");
      expect(screen.getByText("group-a")).toBeInTheDocument();

      await user.click(screen.getByRole("button", { name: "mute-first-row" }));

      expect(screen.getByTestId("row-count")).toHaveTextContent("2");
      expect(screen.queryByText("group-a")).not.toBeInTheDocument();
      expect(screen.getByText("group-b")).toBeInTheDocument();

      const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) ?? "{}");
      expect(Object.keys(stored)).toContain("group-a");
    });

    it("keeps muted groups visible when 'Include muted findings' is active (matches post-reload state)", async () => {
      const user = userEvent.setup();
      render(
        <FindingsGroupTable
          data={[buildGroup("group-a"), buildGroup("group-b")]}
          resolvedFilters={{ "filter[muted]": "include" }}
          hasHistoricalData={false}
        />,
      );

      expect(screen.getByTestId("row-count")).toHaveTextContent("2");

      await user.click(screen.getByRole("button", { name: "mute-first-row" }));

      expect(screen.getByTestId("row-count")).toHaveTextContent("2");
      expect(screen.getByText("group-a")).toBeInTheDocument();
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    });

    it("is a no-op when onMuteComplete fires without IDs (resource-level mute)", async () => {
      const user = userEvent.setup();
      render(
        <FindingsGroupTable
          data={[buildGroup("group-a"), buildGroup("group-b")]}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      expect(screen.getByTestId("row-count")).toHaveTextContent("2");

      await user.click(
        screen.getByRole("button", { name: "mute-without-ids" }),
      );

      expect(screen.getByTestId("row-count")).toHaveTextContent("2");
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    });

    it("hydrates from sessionStorage on mount", () => {
      sessionStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          "group-a": { expiresAt: Date.now() + 60_000 },
        }),
      );

      render(
        <FindingsGroupTable
          data={[buildGroup("group-a"), buildGroup("group-b")]}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      expect(screen.getByTestId("row-count")).toHaveTextContent("1");
      expect(screen.queryByText("group-a")).not.toBeInTheDocument();
      expect(screen.getByText("group-b")).toBeInTheDocument();
    });

    it("removes the storage entry once the server payload no longer includes the group", async () => {
      sessionStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          "group-a": { expiresAt: Date.now() + 60_000 },
        }),
      );

      const { rerender } = render(
        <FindingsGroupTable
          data={[buildGroup("group-a"), buildGroup("group-b")]}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      expect(screen.getByTestId("row-count")).toHaveTextContent("1");

      rerender(
        <FindingsGroupTable
          data={[buildGroup("group-b")]}
          resolvedFilters={{}}
          hasHistoricalData={false}
        />,
      );

      expect(screen.getByTestId("row-count")).toHaveTextContent("1");
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });
});
