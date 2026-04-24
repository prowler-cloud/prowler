import type { ColumnDef } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { MetaDataProps } from "@/types";

import { DataTable } from "./data-table";

vi.mock("next/navigation", () => ({
  usePathname: () => "/findings",
  useRouter: () => ({
    push: vi.fn(),
  }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/contexts", () => ({
  useFilterTransitionOptional: () => null,
}));

vi.mock("@/lib", () => ({
  cn: (...classes: Array<string | false | null | undefined>) =>
    classes.filter(Boolean).join(" "),
  getPaginationInfo: (metadata: MetaDataProps) => ({
    currentPage: metadata.pagination.page,
    totalPages: metadata.pagination.pages,
    totalEntries: metadata.pagination.count,
    itemsPerPageOptions: metadata.pagination.itemsPerPage ?? [10, 20, 50],
  }),
}));

interface TestRow {
  name: string;
}

const columns: ColumnDef<TestRow>[] = [
  {
    accessorKey: "name",
    header: "Name",
  },
];

const metadata: MetaDataProps = {
  pagination: {
    page: 1,
    pages: 1,
    count: 7,
  },
  version: "v1",
};

describe("DataTable", () => {
  describe("when toolbar right content is provided", () => {
    it("should render it before the total entries count", () => {
      // Given
      render(
        <DataTable
          columns={columns}
          data={[{ name: "Finding A" }]}
          metadata={metadata}
          toolbarRightContent={<span>Include muted findings</span>}
        />,
      );

      // When
      const toolbarContent = screen.getByText("Include muted findings");
      const totalEntries = screen.getByText("7 Total Entries");
      const tableContainerText =
        toolbarContent.parentElement?.textContent ?? "";

      // Then
      expect(toolbarContent).toBeInTheDocument();
      expect(totalEntries).toBeInTheDocument();
      expect(tableContainerText.indexOf("Include muted findings")).toBeLessThan(
        tableContainerText.indexOf("7 Total Entries"),
      );
    });
  });
});
