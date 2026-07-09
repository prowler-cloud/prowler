import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ProviderBreakdownEntry } from "../_types";
import { ProviderCoverageCard } from "./provider-coverage-card";

const breakdown: ProviderBreakdownEntry[] = [
  {
    provider: "aws",
    pass: 8,
    fail: 2,
    manual: 1,
    total: 11,
    score: 80,
    unscanned: false,
  },
  {
    provider: "azure",
    pass: 1,
    fail: 3,
    manual: 0,
    total: 4,
    score: 25,
    unscanned: false,
  },
  {
    provider: "gcp",
    pass: 0,
    fail: 0,
    manual: 0,
    total: 0,
    score: 0,
    unscanned: true,
  },
];

describe("ProviderCoverageCard", () => {
  it("lists each scanned provider with its pass score", () => {
    render(<ProviderCoverageCard breakdown={breakdown} />);

    expect(screen.getByText("Provider Coverage")).toBeInTheDocument();
    const aws = screen.getByTestId("coverage-row-aws");
    expect(aws).toHaveTextContent("AWS");
    expect(aws).toHaveTextContent("80%");
    expect(screen.getByTestId("coverage-row-azure")).toHaveTextContent("25%");
  });

  it("shows compatible-but-unscanned providers without a score", () => {
    render(<ProviderCoverageCard breakdown={breakdown} />);

    const gcp = screen.getByTestId("coverage-row-gcp");
    expect(gcp).toHaveTextContent(/no completed scan/i);
    expect(gcp).not.toHaveTextContent("%");
  });
});
