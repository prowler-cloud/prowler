import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SCAN_JOBS_TAB } from "@/types";

import { ScansFilterBar } from "./scans-filter-bar";

vi.mock("@/components/filters/provider-account-selectors", () => ({
  ProviderAccountSelectors: () => <div>Provider account selectors</div>,
}));

vi.mock("@/components/shadcn", () => ({
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
  }) => <div data-value={value}>{children}</div>,
  SelectTrigger: ({ children, ...props }: React.ComponentProps<"button">) => (
    <button {...props}>{children}</button>
  ),
  SelectValue: ({ placeholder }: { placeholder: string }) => (
    <span>{placeholder}</span>
  ),
}));

const defaultProps = {
  providers: [],
  scheduleType: "all",
  scanStatus: "all",
  showStatusFilter: false,
  onScheduleTypeChange: vi.fn(),
  onScanStatusChange: vi.fn(),
};

describe("ScansFilterBar", () => {
  it("hides the type filter on the scheduled tab", () => {
    // Given
    render(
      <ScansFilterBar {...defaultProps} activeTab={SCAN_JOBS_TAB.SCHEDULED} />,
    );

    // Then
    expect(
      screen.queryByRole("button", { name: /all types/i }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Provider account selectors")).toBeInTheDocument();
  });

  it("shows the type filter outside the scheduled tab", () => {
    // Given
    render(
      <ScansFilterBar {...defaultProps} activeTab={SCAN_JOBS_TAB.COMPLETED} />,
    );

    // Then
    expect(screen.getByRole("button", { name: /all types/i })).toBeVisible();
  });
});
