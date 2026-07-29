import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { CheckFindingsSSR } from "./check-findings.ssr";

vi.mock("@/actions/overview", () => ({
  getFindingsByStatus: vi.fn(async () => ({
    data: {
      attributes: { fail: 80, pass: 320, fail_new: 7, pass_new: 12 },
    },
  })),
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="status-context">{JSON.stringify(item)}</output>
  ),
}));

vi.mock("../status-chart/_components/status-chart", () => ({
  StatusChart: () => <div>chart</div>,
}));

describe("CheckFindingsSSR", () => {
  it("publishes the findings status summary as Lighthouse context", async () => {
    render(await CheckFindingsSSR({ searchParams: {} }));

    const context = screen.getByTestId("status-context");
    expect(context).toHaveTextContent('"id":"status-summary"');
    expect(context).toHaveTextContent('"scopeKey":"overview:/"');
    expect(context).toHaveTextContent('"passed":320');
    expect(context).toHaveTextContent('"failed":80');
    expect(context).toHaveTextContent('"newPassed":12');
    expect(context).toHaveTextContent('"newFailed":7');
  });
});
