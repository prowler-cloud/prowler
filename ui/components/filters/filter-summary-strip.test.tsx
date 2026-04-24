import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

// Mock lucide-react to avoid SVG rendering issues in jsdom
vi.mock("lucide-react", () => ({
  X: () => <svg data-testid="x-icon" />,
}));

// Mock @/components/shadcn to avoid next-auth import chain
vi.mock("@/components/shadcn", () => ({
  Badge: ({
    children,
    className,
    variant,
  }: {
    children: React.ReactNode;
    className?: string;
    variant?: string;
  }) => (
    <span data-testid="badge" data-variant={variant} className={className}>
      {children}
    </span>
  ),
  Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  TooltipContent: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
  TooltipTrigger: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
}));

vi.mock("@/lib/utils", () => ({
  cn: (...classes: (string | undefined | false)[]) =>
    classes.filter(Boolean).join(" "),
}));

import {
  FilterChip,
  FilterSummaryStrip,
} from "@/components/filters/filter-summary-strip";

// ── Future E2E coverage ────────────────────────────────────────────────────
// TODO (E2E): Full filter strip flow should be covered in Playwright tests:
// - Filter chips appear after staging selections in the findings page
// - Removing a chip via the X button un-stages that filter value
// - Chips disappear after applying filters (pending state resets to URL state)
// ──────────────────────────────────────────────────────────────────────────

const mockChips: FilterChip[] = [
  { key: "filter[severity__in]", label: "Severity", value: "critical" },
  { key: "filter[severity__in]", label: "Severity", value: "high" },
  { key: "filter[status__in]", label: "Status", value: "FAIL" },
];

describe("FilterSummaryStrip", () => {
  // ── Empty state ──────────────────────────────────────────────────────────

  describe("when chips array is empty", () => {
    it("should not render anything", () => {
      // Given
      const onRemove = vi.fn();

      // When
      const { container } = render(
        <FilterSummaryStrip chips={[]} onRemove={onRemove} />,
      );

      // Then
      expect(container.firstChild).toBeNull();
    });
  });

  // ── Chip rendering ───────────────────────────────────────────────────────

  describe("when chips are provided", () => {
    it("should render a chip for each filter value", () => {
      // Given
      const onRemove = vi.fn();

      // When
      render(<FilterSummaryStrip chips={mockChips} onRemove={onRemove} />);

      // Then — 3 chips should be visible (2 severity + 1 status)
      expect(screen.getAllByTestId("badge")).toHaveLength(3);
    });

    it("should display the label and value text for each chip", () => {
      // Given
      const onRemove = vi.fn();

      // When
      render(
        <FilterSummaryStrip
          chips={[
            {
              key: "filter[severity__in]",
              label: "Severity",
              value: "critical",
            },
          ]}
          onRemove={onRemove}
        />,
      );

      // Then
      expect(screen.getByText("Severity:")).toBeInTheDocument();
      expect(screen.getByText("critical")).toBeInTheDocument();
    });

    it("should display displayValue when provided instead of value", () => {
      // Given
      const onRemove = vi.fn();

      // When
      render(
        <FilterSummaryStrip
          chips={[
            {
              key: "filter[status__in]",
              label: "Status",
              value: "FAIL",
              displayValue: "Failed",
            },
          ]}
          onRemove={onRemove}
        />,
      );

      // Then — displayValue takes precedence
      expect(screen.getByText("Failed")).toBeInTheDocument();
      expect(screen.queryByText("FAIL")).not.toBeInTheDocument();
    });

    it("should render an aria-label region for accessibility", () => {
      // Given
      const onRemove = vi.fn();

      // When
      render(<FilterSummaryStrip chips={mockChips} onRemove={onRemove} />);

      // Then
      expect(
        screen.getByRole("region", { name: "Active filters" }),
      ).toBeInTheDocument();
    });

    it("should not add vertical padding around the chip strip", () => {
      // Given
      const onRemove = vi.fn();

      // When
      render(<FilterSummaryStrip chips={mockChips} onRemove={onRemove} />);

      // Then
      expect(
        screen.getByRole("region", { name: "Active filters" }),
      ).not.toHaveClass("py-2");
    });
  });

  // ── onRemove interaction ─────────────────────────────────────────────────

  describe("onRemove", () => {
    it("should call onRemove with correct filterKey and value when X is clicked", async () => {
      // Given
      const user = userEvent.setup();
      const onRemove = vi.fn();

      render(
        <FilterSummaryStrip
          chips={[
            {
              key: "filter[severity__in]",
              label: "Severity",
              value: "critical",
            },
          ]}
          onRemove={onRemove}
        />,
      );

      // When
      const removeButton = screen.getByRole("button", {
        name: /Remove Severity filter: critical/i,
      });
      await user.click(removeButton);

      // Then
      expect(onRemove).toHaveBeenCalledTimes(1);
      expect(onRemove).toHaveBeenCalledWith("filter[severity__in]", "critical");
    });

    it("should call onRemove with the correct chip when there are multiple chips", async () => {
      // Given
      const user = userEvent.setup();
      const onRemove = vi.fn();

      render(<FilterSummaryStrip chips={mockChips} onRemove={onRemove} />);

      // When — click the X button for "high" severity
      const removeHighButton = screen.getByRole("button", {
        name: /Remove Severity filter: high/i,
      });
      await user.click(removeHighButton);

      // Then
      expect(onRemove).toHaveBeenCalledWith("filter[severity__in]", "high");
      expect(onRemove).toHaveBeenCalledTimes(1);
    });
  });
});
