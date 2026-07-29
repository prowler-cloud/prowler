import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ThreatScoreSSR } from "./threat-score.ssr";

vi.mock("@/actions/overview", () => ({
  getThreatScore: vi.fn(async () => ({
    data: [
      {
        attributes: {
          overall_score: "72",
          score_delta: "2",
          section_scores: {},
          critical_requirements: [],
        },
      },
    ],
  })),
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="overview-context">{JSON.stringify(item)}</output>
  ),
}));

vi.mock("./_components/threat-score", () => ({
  ThreatScore: ({ score }: { score?: number }) => <div>Score {score}</div>,
}));

describe("ThreatScoreSSR", () => {
  it("publishes the loaded overview score as Lighthouse context", async () => {
    render(await ThreatScoreSSR({ searchParams: {} }));

    expect(screen.getByTestId("overview-context")).toHaveTextContent(
      '"score":72',
    );
    expect(screen.getByText("Score 72")).toBeInTheDocument();
  });
});
