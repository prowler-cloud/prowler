import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { FindingsGroupTable } from "./findings-group-table";

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: vi.fn(),
  }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/ui/table", () => ({
  DataTable: ({ toolbarRightContent }: { toolbarRightContent?: ReactNode }) => (
    <div>
      <div data-testid="table-toolbar-right">{toolbarRightContent}</div>
      <span>10 Total Entries</span>
    </div>
  ),
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
});
