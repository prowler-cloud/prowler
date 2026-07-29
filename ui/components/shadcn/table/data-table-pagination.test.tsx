import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { MetaDataProps } from "@/types";

vi.mock("next/navigation", () => ({
  usePathname: () => "/providers",
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
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
  Select: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
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
  SelectValue: () => <span>10</span>,
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
});
