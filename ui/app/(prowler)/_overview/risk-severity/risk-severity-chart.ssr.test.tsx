import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { getFindingsBySeverity } from "@/actions/overview";

import { RiskSeverityChartSSR } from "./risk-severity-chart.ssr";

vi.mock("@/actions/overview", () => ({
  getFindingsBySeverity: vi.fn(async () => ({
    data: {
      attributes: {
        critical: 4,
        high: 18,
        medium: 40,
        low: 15,
        informational: 3,
      },
    },
  })),
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="severity-context">{JSON.stringify(item)}</output>
  ),
}));

vi.mock("./_components/risk-severity-chart", () => ({
  RiskSeverityChart: () => <div>chart</div>,
}));

describe("RiskSeverityChartSSR", () => {
  it("publishes the failing severity breakdown as Lighthouse context", async () => {
    render(await RiskSeverityChartSSR({ searchParams: {} }));

    const context = screen.getByTestId("severity-context");
    expect(context).toHaveTextContent('"id":"severity-summary"');
    expect(context).toHaveTextContent('"scopeKey":"overview:/"');
    expect(context).toHaveTextContent(
      '"severityCounts":{"critical":4,"high":18,"medium":40,"low":15,"informational":3}',
    );
  });

  it("renders the error state and publishes no context on a 4xx response", async () => {
    // handleApiResponse resolves truthy {error, status} objects for 4xx.
    vi.mocked(getFindingsBySeverity).mockResolvedValueOnce({
      error: "Invalid filter",
      status: 400,
    } as unknown as Awaited<ReturnType<typeof getFindingsBySeverity>>);

    render(await RiskSeverityChartSSR({ searchParams: {} }));

    expect(
      screen.getByText("Failed to load severity data"),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("severity-context")).not.toBeInTheDocument();
  });

  it("renders the error state and publishes no context on an empty body", async () => {
    // handleApiResponse resolves {success, status} for 204 and empty bodies.
    vi.mocked(getFindingsBySeverity).mockResolvedValueOnce({
      success: true,
      status: 204,
    } as unknown as Awaited<ReturnType<typeof getFindingsBySeverity>>);

    render(await RiskSeverityChartSSR({ searchParams: {} }));

    expect(
      screen.getByText("Failed to load severity data"),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("severity-context")).not.toBeInTheDocument();
  });
});
