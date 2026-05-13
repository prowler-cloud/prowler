import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CustomCheckboxMutedFindings } from "./custom-checkbox-muted-findings";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams("filter%5Bmuted%5D=false"),
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({
    navigateWithParams: vi.fn(),
  }),
}));

vi.mock("@/lib", () => ({
  MUTED_FILTER: {
    EXCLUDE: "false",
    INCLUDE: "include",
  },
}));

vi.mock("@/components/icons", () => ({
  MutedIcon: ({ className }: { className?: string }) => (
    <svg aria-hidden="true" className={className} data-slot="muted-icon" />
  ),
}));

describe("CustomCheckboxMutedFindings", () => {
  it("should show the muted icon before the label text", () => {
    // Given
    const { container } = render(<CustomCheckboxMutedFindings />);

    // When
    const checkbox = screen.getByRole("checkbox", {
      name: "Include muted findings",
    });
    const mutedIcon = container.querySelector('[data-slot="muted-icon"]');
    const labelText = screen.getByText("Include muted findings");
    const wrapperText = checkbox.parentElement?.textContent ?? "";

    // Then
    expect(checkbox).toBeInTheDocument();
    expect(mutedIcon).toBeInTheDocument();
    expect(mutedIcon?.compareDocumentPosition(labelText)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
    expect(wrapperText).toContain("Include muted findings");
  });
});
