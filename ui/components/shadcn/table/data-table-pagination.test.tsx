import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { MetaDataProps } from "@/types";

const mocks = vi.hoisted(() => ({ searchParams: new URLSearchParams() }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/providers",
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => mocks.searchParams,
}));

vi.mock("@/lib", () => ({
  getPaginationInfo: (metadata: MetaDataProps) => ({
    currentPage: metadata.pagination.page,
    totalPages: metadata.pagination.pages,
    totalEntries: metadata.pagination.count,
    itemsPerPageOptions: metadata.pagination.itemsPerPage ?? [10, 20, 50],
  }),
}));

vi.mock("@/components/shadcn/select/select", () => ({
  // data-value stands in for the trigger label
  Select: ({
    value,
    children,
  }: {
    value: string;
    children: React.ReactNode;
  }) => (
    <div data-testid="page-size-select" data-value={value}>
      {children}
    </div>
  ),
  SelectContent: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  SelectItem: ({
    children,
    value,
  }: {
    children: React.ReactNode;
    value: string;
  }) => <option value={value}>{children}</option>,
  SelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <button type="button">{children}</button>
  ),
  SelectValue: () => null,
}));

import { DataTablePagination } from "./data-table-pagination";

const metadata: MetaDataProps = {
  pagination: {
    page: 2,
    pages: 4,
    count: 40,
    itemsPerPage: [10, 20, 50],
  },
  version: "latest",
};

describe("DataTablePagination", () => {
  beforeEach(() => {
    mocks.searchParams = new URLSearchParams();
  });

  it("keeps navigation arrows visible on hover in light theme", () => {
    render(<DataTablePagination metadata={metadata} />);

    expect(screen.getByLabelText("Go to first page")).toHaveClass(
      "hover:text-text-neutral-primary",
    );
    expect(screen.getByLabelText("Go to first page")).toHaveClass(
      "hover:bg-bg-neutral-tertiary",
    );
    expect(screen.getByLabelText("Go to next page")).toHaveClass(
      "hover:text-text-neutral-primary",
    );
  });

  it("does not render an empty pagination container when there is only one page", () => {
    // Given - Metadata for a table that does not need pagination
    const singlePageMetadata: MetaDataProps = {
      pagination: {
        page: 1,
        pages: 1,
        count: 1,
        itemsPerPage: [10, 20, 50],
      },
      version: "latest",
    };

    // When - Rendering pagination
    const { container } = render(
      <DataTablePagination metadata={singlePageMetadata} />,
    );

    // Then - No wrapper remains to add extra DataTable gap
    expect(container).toBeEmptyDOMElement();
  });

  it("keeps the rows-per-page selector when the chosen page size collapses the table to a single page", () => {
    const collapsedByPageSize: MetaDataProps = {
      pagination: {
        page: 1,
        pages: 1,
        count: 85,
        itemsPerPage: [10, 20, 30, 50, 100],
      },
      version: "latest",
    };
    mocks.searchParams = new URLSearchParams("pageSize=100");

    render(<DataTablePagination metadata={collapsedByPageSize} />);

    expect(screen.getByText("Rows per page")).toBeInTheDocument();
    expect(screen.getByTestId("page-size-select")).toHaveAttribute(
      "data-value",
      "100",
    );
    expect(screen.queryByLabelText("Go to next page")).not.toBeInTheDocument();
    expect(screen.queryByText(/^Page \d+ of \d+$/)).not.toBeInTheDocument();
  });

  it("keeps the selector when the smallest configured page size would still paginate", () => {
    const smallestOptionPaginates: MetaDataProps = {
      pagination: {
        page: 1,
        pages: 1,
        count: 7,
        itemsPerPage: [5, 10, 25],
      },
      version: "latest",
    };

    render(<DataTablePagination metadata={smallestOptionPaginates} />);

    expect(screen.getByText("Rows per page")).toBeInTheDocument();
  });

  it("hides the selector when no page size option would split the table", () => {
    const nothingToPaginate: MetaDataProps = {
      pagination: {
        page: 1,
        pages: 1,
        count: 7,
        itemsPerPage: [10, 20, 50],
      },
      version: "latest",
    };

    const { container } = render(
      <DataTablePagination metadata={nothingToPaginate} />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("follows the page size in the URL when it changes under the mounted selector", () => {
    mocks.searchParams = new URLSearchParams("pageSize=100");
    const { rerender } = render(<DataTablePagination metadata={metadata} />);

    expect(screen.getByTestId("page-size-select")).toHaveAttribute(
      "data-value",
      "100",
    );

    // URL changes without remounting: back/forward, filter reset
    mocks.searchParams = new URLSearchParams("pageSize=20");
    rerender(<DataTablePagination metadata={metadata} />);

    expect(screen.getByTestId("page-size-select")).toHaveAttribute(
      "data-value",
      "20",
    );
  });
});
