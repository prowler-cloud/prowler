import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

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
});
