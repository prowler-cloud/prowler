import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

// Mock lucide-react to avoid SVG rendering issues in jsdom
vi.mock("lucide-react", () => ({
  Check: () => <svg data-testid="check-icon" />,
}));

// Mock @/components/shadcn to avoid next-auth import chain
vi.mock("@/components/shadcn", () => ({
  Button: ({
    children,
    disabled,
    onClick,
    "aria-label": ariaLabel,
    variant,
    size,
  }: {
    children?: React.ReactNode;
    disabled?: boolean;
    onClick?: () => void;
    "aria-label"?: string;
    variant?: string;
    size?: string;
  }) => (
    <button
      disabled={disabled}
      onClick={onClick}
      aria-label={ariaLabel}
      data-variant={variant}
      data-size={size}
    >
      {children}
    </button>
  ),
}));

vi.mock("@/lib/utils", () => ({
  cn: (...classes: (string | undefined | false)[]) =>
    classes.filter(Boolean).join(" "),
}));

import { ApplyFiltersButton } from "@/components/filters/apply-filters-button";

// ── Future E2E coverage ────────────────────────────────────────────────────
// TODO (E2E): Full apply-filters button flow should be covered in Playwright tests:
// - Button appears disabled when no filters have been staged
// - Button shows correct count after staging multiple filters
// - Clicking Apply pushes all pending filters to the URL in one navigation event
// - Clicking Discard resets pending state to current URL state (staged filters disappear)
// ──────────────────────────────────────────────────────────────────────────

describe("ApplyFiltersButton", () => {
  // ── No changes ───────────────────────────────────────────────────────────

  describe("when hasChanges is false", () => {
    it("should render the Apply Filters button as disabled", () => {
      // Given / When
      render(
        <ApplyFiltersButton
          hasChanges={false}
          changeCount={0}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      const applyButton = screen.getByRole("button", {
        name: "Apply Filters",
      });
      expect(applyButton).toBeDisabled();
    });

    it("should NOT render the Undo button when there are no changes", () => {
      // Given / When
      render(
        <ApplyFiltersButton
          hasChanges={false}
          changeCount={0}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      expect(
        screen.queryByRole("button", {
          name: /undo/i,
        }),
      ).not.toBeInTheDocument();
    });

    it("should show 'Apply Filters' label without count", () => {
      // Given / When
      render(
        <ApplyFiltersButton
          hasChanges={false}
          changeCount={0}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      expect(
        screen.getByRole("button", { name: "Apply Filters" }),
      ).toBeInTheDocument();
    });

    it("should not render an icon in the Apply Filters button", () => {
      // Given / When
      render(
        <ApplyFiltersButton
          hasChanges={false}
          changeCount={0}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      const applyButton = screen.getByRole("button", {
        name: "Apply Filters",
      });
      expect(applyButton).not.toContainElement(
        screen.queryByTestId("check-icon"),
      );
    });
  });

  // ── Has changes ──────────────────────────────────────────────────────────

  describe("when hasChanges is true", () => {
    it("should render the Apply Filters button as enabled", () => {
      // Given / When
      render(
        <ApplyFiltersButton
          hasChanges={true}
          changeCount={2}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      const applyButton = screen.getByRole("button", {
        name: "Apply Filters (2)",
      });
      expect(applyButton).not.toBeDisabled();
    });

    it("should show the change count in the button label", () => {
      // Given / When
      render(
        <ApplyFiltersButton
          hasChanges={true}
          changeCount={3}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      expect(
        screen.getByRole("button", { name: "Apply Filters (3)" }),
      ).toBeInTheDocument();
    });

    it("should show 'Apply Filters' (without count) when changeCount is 0 but hasChanges is true", () => {
      // Given — hasChanges=true but changeCount=0 (edge case)
      render(
        <ApplyFiltersButton
          hasChanges={true}
          changeCount={0}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      expect(
        screen.getByRole("button", { name: "Apply Filters" }),
      ).toBeInTheDocument();
    });

    it("should render the Undo button", () => {
      // Given / When
      render(
        <ApplyFiltersButton
          hasChanges={true}
          changeCount={1}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      expect(
        screen.getByRole("button", { name: /undo pending filter changes/i }),
      ).toBeInTheDocument();
    });

    it("should use the same spacing between Apply Filters and Undo as the filters action row", () => {
      // Given / When
      render(
        <ApplyFiltersButton
          hasChanges={true}
          changeCount={1}
          onApply={vi.fn()}
          onDiscard={vi.fn()}
        />,
      );

      // Then
      const applyButton = screen.getByRole("button", {
        name: "Apply Filters (1)",
      });
      expect(applyButton.parentElement).toHaveClass("gap-2");
    });
  });

  // ── onApply interaction ──────────────────────────────────────────────────

  describe("onApply", () => {
    it("should call onApply when the Apply Filters button is clicked", async () => {
      // Given
      const user = userEvent.setup();
      const onApply = vi.fn();
      const onDiscard = vi.fn();

      render(
        <ApplyFiltersButton
          hasChanges={true}
          changeCount={1}
          onApply={onApply}
          onDiscard={onDiscard}
        />,
      );

      // When
      await user.click(
        screen.getByRole("button", { name: "Apply Filters (1)" }),
      );

      // Then
      expect(onApply).toHaveBeenCalledTimes(1);
      expect(onDiscard).not.toHaveBeenCalled();
    });

    it("should NOT call onApply when the button is disabled", async () => {
      // Given
      const user = userEvent.setup();
      const onApply = vi.fn();

      render(
        <ApplyFiltersButton
          hasChanges={false}
          changeCount={0}
          onApply={onApply}
          onDiscard={vi.fn()}
        />,
      );

      // When
      await user.click(screen.getByRole("button", { name: "Apply Filters" }));

      // Then — disabled button should not fire
      expect(onApply).not.toHaveBeenCalled();
    });
  });

  // ── onDiscard interaction ────────────────────────────────────────────────

  describe("onDiscard", () => {
    it("should call onDiscard when the Undo button is clicked", async () => {
      // Given
      const user = userEvent.setup();
      const onApply = vi.fn();
      const onDiscard = vi.fn();

      render(
        <ApplyFiltersButton
          hasChanges={true}
          changeCount={2}
          onApply={onApply}
          onDiscard={onDiscard}
        />,
      );

      // When
      await user.click(
        screen.getByRole("button", { name: /undo pending filter changes/i }),
      );

      // Then
      expect(onDiscard).toHaveBeenCalledTimes(1);
      expect(onApply).not.toHaveBeenCalled();
    });
  });
});
