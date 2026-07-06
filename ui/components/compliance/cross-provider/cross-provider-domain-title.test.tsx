import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { DomainStats } from "@/lib/compliance/cross-provider-insights";

import { CrossProviderDomainTitle } from "./cross-provider-domain-title";

const makeStats = (overrides: Partial<DomainStats> = {}): DomainStats => ({
  name: "1. Inventory and Control of Enterprise Assets",
  total: 5,
  pass: 1,
  fail: 2,
  manual: 2,
  byProvider: {},
  ...overrides,
});

describe("CrossProviderDomainTitle", () => {
  it("reserves a fixed width for the counts column regardless of digit count", () => {
    // Regression guard: the name column is flex-1 (grows to fill whatever's
    // left on the line) — if the counts column were only ``shrink-0``
    // instead of a fixed width, a row with double/triple-digit counts would
    // shrink the name column by the difference, shifting the heatmap that
    // follows it to a different x than on rows with single-digit counts.
    const { container } = render(
      <CrossProviderDomainTitle
        name="Single-digit counts"
        stats={makeStats({ pass: 1, fail: 2, manual: 2 })}
        providers={["aws", "azure"]}
      />,
    );

    const countsContainer = screen.getByText("1").closest("div");
    expect(countsContainer).toHaveClass("w-[104px]");
    expect(container).toBeTruthy();
  });

  it("renders the same fixed-width class for triple-digit counts", () => {
    render(
      <CrossProviderDomainTitle
        name="Triple-digit counts"
        stats={makeStats({ total: 153, pass: 100, fail: 40, manual: 13 })}
        providers={["aws", "azure"]}
      />,
    );

    const countsContainer = screen.getByText("100").closest("div");
    expect(countsContainer).toHaveClass("w-[104px]");
  });

  it("renders one heatmap cell per provider with the rolled-up status in its accessible name", () => {
    render(
      <CrossProviderDomainTitle
        name="Provider heatmap"
        stats={makeStats({ byProvider: { aws: "PASS", azure: "FAIL" } })}
        providers={["aws", "azure", "gcp"]}
      />,
    );

    expect(screen.getByLabelText(/AWS: PASS/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Azure: FAIL/)).toBeInTheDocument();
    // gcp has no entry in byProvider — falls back to "no scan".
    expect(screen.getByLabelText(/Google Cloud.*no scan/)).toBeInTheDocument();
  });

  it("shows the pass/fail/manual counts", () => {
    render(
      <CrossProviderDomainTitle
        name="Counts"
        stats={makeStats({ pass: 7, fail: 3, manual: 1 })}
        providers={["aws"]}
      />,
    );

    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument();
  });
});
