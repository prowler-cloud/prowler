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

const columnsWithActions: ColumnDef<TestRow>[] = [
  {
    accessorKey: "name",
    header: "Name",
  },
  {
    id: "actions",
    header: "",
    cell: () => <button type="button">Actions</button>,
    enableSorting: false,
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

    it("should stack the right content below search on narrow screens", () => {
      // Given
      render(
        <DataTable
          columns={columns}
          data={[{ name: "Finding A" }]}
          metadata={metadata}
          showSearch
          toolbarRightContent={<span>Include muted findings</span>}
        />,
      );

      // When
      const toolbar = screen.getByTestId("data-table-toolbar");
      const rightContent = screen.getByTestId("data-table-toolbar-right");

      // Then
      expect(toolbar).toHaveClass("flex-col");
      expect(toolbar).toHaveClass("md:flex-row");
      expect(rightContent).toHaveClass("w-full");
      expect(rightContent).toHaveClass("md:w-auto");
    });
  });

  describe("when an actions column is present", () => {
    it("should keep the actions header and cells sticky on the right edge", () => {
      // Given
      render(
        <DataTable
          columns={columnsWithActions}
          data={[{ name: "Finding A" }]}
        />,
      );

      // When
      const columnHeaders = screen.getAllByRole("columnheader");
      const nameHeader = columnHeaders[0];
      const actionsHeader = columnHeaders.at(-1);
      expect(actionsHeader).toBeDefined();
      const actionsHeaderElement = actionsHeader as HTMLElement;
      const nameCell = screen.getByText("Finding A").closest("td");
      const actionsCell = screen
        .getByRole("button", {
          name: "Actions",
        })
        .closest("td");

      // Then
      expect(nameHeader).not.toHaveClass("sticky");
      expect(nameCell).not.toHaveClass("sticky");
      expect(nameHeader).toHaveClass("pr-6");
      expect(nameCell).toHaveClass("pr-6");
      expect(actionsHeaderElement).not.toHaveClass("sticky");
      expect(actionsHeaderElement).not.toHaveClass("pr-6");
      expect(actionsHeaderElement).not.toHaveClass("right-0");
      expect(actionsHeaderElement).not.toHaveClass("z-20");
      expect(actionsHeaderElement).toHaveClass("bg-bg-neutral-tertiary");
      expect(actionsHeaderElement).toHaveClass("border-y");
      expect(actionsHeaderElement).toHaveClass("last:border-r");
      expect(actionsHeaderElement).toHaveClass("last:rounded-r-full");
      expect(actionsHeaderElement).not.toHaveClass("bg-transparent");
      expect(actionsHeaderElement).not.toHaveClass("border-y-0");
      expect(actionsHeaderElement).not.toHaveClass("border-l-0");
      expect(actionsHeaderElement).not.toHaveClass("border-r-0");
      expect(actionsHeaderElement).not.toHaveClass("last:border-r-0");
      expect(actionsHeaderElement).not.toHaveClass("backdrop-blur-none");
      expect(actionsHeaderElement).not.toHaveClass("last:rounded-r-none");
      expect(actionsHeaderElement).not.toHaveClass("before:bg-gradient-to-r");
      expect(actionsHeaderElement).not.toHaveClass("before:content-['']");
      expect(actionsHeaderElement).not.toHaveClass("after:content-['']");
      expect(actionsHeaderElement).not.toHaveClass("after:rounded-r-full");
      expect(actionsHeaderElement.querySelector("div")).not.toBeInTheDocument();
      expect(actionsCell).toHaveClass("sticky");
      expect(actionsCell).not.toHaveClass("pr-6");
      expect(actionsCell).toHaveClass("right-0");
      expect(actionsCell).toHaveClass("z-20");
      expect(actionsCell).toHaveClass("bg-bg-neutral-secondary");
      expect(actionsCell).toHaveClass("last:rounded-r-none!");
      expect(actionsCell).not.toHaveClass("border-l");
      expect(actionsCell).toHaveClass("before:bg-gradient-to-r");
      expect(actionsCell).toHaveClass("before:from-transparent");
      expect(actionsCell).toHaveClass("before:to-bg-neutral-secondary");
    });
  });
});
