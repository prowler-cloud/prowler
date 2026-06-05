import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { DataTableSearch } from "./data-table-search";

vi.mock("next/navigation", () => ({
  usePathname: () => "/findings",
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({ updateFilter: vi.fn() }),
}));

describe("DataTableSearch", () => {
  it("uses visible focus and icon microinteraction timing", async () => {
    // Given - A table search field
    const user = userEvent.setup();
    render(<DataTableSearch placeholder="Search findings" />);

    // When - The user focuses the table search
    const input = screen.getByRole("searchbox", { name: /search findings/i });
    await user.click(input);

    const control = screen.getByTestId("data-table-search-control");
    const icon = screen.getByTestId("data-table-search-icon");

    // Then - The table search control has visible focus/highlight timing
    expect(control).toHaveClass(
      "transition-[background-color,border-color,box-shadow,color]",
      "duration-250",
      "ease-out",
      "motion-reduce:transition-none",
      "focus-within:ring-1",
    );
    expect(icon).toHaveClass(
      "transition-colors",
      "duration-250",
      "ease-out",
      "motion-reduce:transition-none",
    );
  });
});
