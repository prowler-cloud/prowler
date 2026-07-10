import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ProviderBreakdownEntry } from "../_types";
import { ProviderCoverageCard } from "./provider-coverage-card";

vi.mock("@/components/icons/providers-badge/provider-type-icon", () => ({
  ProviderTypeIcon: () => <span aria-hidden="true" />,
}));

const scannedProvider: ProviderBreakdownEntry = {
  provider: "aws",
  pass: 8,
  fail: 2,
  manual: 1,
  total: 11,
  score: 80,
  unscanned: false,
};

const unscannedProvider: ProviderBreakdownEntry = {
  provider: "gcp",
  pass: 0,
  fail: 0,
  manual: 0,
  total: 0,
  score: 0,
  unscanned: true,
};

describe("ProviderCoverageCard", () => {
  it("shows only providers that have a scan", () => {
    // Given / When
    render(
      <ProviderCoverageCard breakdown={[scannedProvider, unscannedProvider]} />,
    );

    // Then
    expect(screen.getByTestId("coverage-row-aws")).toBeInTheDocument();
    expect(screen.queryByTestId("coverage-row-gcp")).not.toBeInTheDocument();
    expect(screen.queryByText("No completed scan")).not.toBeInTheDocument();
  });

  it("shows an empty state when no provider has a scan", () => {
    // Given / When
    render(<ProviderCoverageCard breakdown={[unscannedProvider]} />);

    // Then
    expect(
      screen.getByText("No scanned providers for this framework yet."),
    ).toBeInTheDocument();
  });
});
