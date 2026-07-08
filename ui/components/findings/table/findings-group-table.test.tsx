import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { FindingsGroupTable } from "./findings-group-table";

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
  }: {
    data?: Array<{ checkId?: string }>;
    toolbarRightContent?: ReactNode;
    getRowAttributes?: (row: {
      index: number;
      original: { checkId?: string };
    }) => Record<string, string | undefined>;
  }) => (
    <div>
      <div data-testid="table-toolbar-right">{toolbarRightContent}</div>
      <span>10 Total Entries</span>
      <table>
        <tbody>
          {(data ?? []).map((original, index) => (
            <tr
              key={original.checkId ?? index}
              data-testid={`row-${index}`}
              {...getRowAttributes?.({ index, original })}
            >
              <td>{original.checkId}</td>
            </tr>
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
  getColumnFindingGroups: () => [],
}));

vi.mock("./inline-resource-container", () => ({
  InlineResourceContainer: () => null,
}));

vi.mock("../floating-mute-button", () => ({
  FloatingMuteButton: () => null,
}));

describe("FindingsGroupTable", () => {
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
});
