import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  usePathname: () => "/findings",
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams("filter[status]=FAIL"),
}));

vi.mock("../shadcn", () => ({
  Button: ({
    children,
    onClick,
    "aria-label": ariaLabel,
    variant,
    size,
  }: {
    children?: React.ReactNode;
    onClick?: () => void;
    "aria-label"?: string;
    variant?: string;
    size?: string;
  }) => (
    <button
      onClick={onClick}
      aria-label={ariaLabel}
      data-variant={variant}
      data-size={size}
    >
      {children}
    </button>
  ),
}));

vi.mock("lucide-react", () => ({
  XCircle: () => <svg data-testid="x-circle-icon" />,
}));

import { ClearFiltersButton } from "@/components/filters/clear-filters-button";

describe("ClearFiltersButton", () => {
  it("should render as outline by default", () => {
    // Given / When
    render(<ClearFiltersButton showCount />);

    // Then
    expect(screen.getByRole("button", { name: "Reset" })).toHaveAttribute(
      "data-variant",
      "outline",
    );
    expect(screen.getByText("Clear All (1)")).toBeInTheDocument();
  });
});
