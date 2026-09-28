import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { getThreatScore } from "@/actions/overview";

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

  it("coerces aggregated string section scores into numeric context", async () => {
    // The multi-provider aggregation branch of /overviews/threatscore
    // serializes section score values as strings.
    vi.mocked(getThreatScore).mockResolvedValueOnce({
      data: [
        {
          attributes: {
            overall_score: "55.20",
            score_delta: null,
            section_scores: { "Attack Surface": "38.60", IAM: "71.50" },
            critical_requirements: [],
          },
        },
      ],
    } as unknown as Awaited<ReturnType<typeof getThreatScore>>);

    render(await ThreatScoreSSR({ searchParams: {} }));

    const context = screen.getByTestId("overview-context");
    expect(context).toHaveTextContent('"worstSection":"Attack Surface"');
    expect(context).toHaveTextContent('"worstSectionScore":38.6');
  });

  it("publishes delta, weakest section, critical count, and totals", async () => {
    vi.mocked(getThreatScore).mockResolvedValueOnce({
      data: [
        {
          attributes: {
            overall_score: "62.4",
            score_delta: "-3.21",
            section_scores: { "Attack Surface": 38.6, IAM: 71.5 },
            critical_requirements: [
              {
                requirement_id: "1.1",
                risk_level: 5,
                weight: 100,
                title: "Root MFA",
              },
              {
                requirement_id: "1.2",
                risk_level: 4,
                weight: 90,
                title: "Public buckets",
              },
            ],
            passed_requirements: 120,
            failed_requirements: 40,
            total_requirements: 160,
          },
        },
      ],
    } as unknown as Awaited<ReturnType<typeof getThreatScore>>);

    render(await ThreatScoreSSR({ searchParams: {} }));

    const context = screen.getByTestId("overview-context");
    expect(context).toHaveTextContent('"scoreDelta":-3.21');
    expect(context).toHaveTextContent('"worstSection":"Attack Surface"');
    expect(context).toHaveTextContent('"worstSectionScore":38.6');
    expect(context).toHaveTextContent('"criticalRequirementsCount":2');
    expect(context).toHaveTextContent(
      '"totals":{"passed":120,"failed":40,"total":160}',
    );
  });

  it("renders the empty state and publishes no context on a 4xx response", async () => {
    // handleApiResponse resolves truthy {error, status} objects for 4xx.
    vi.mocked(getThreatScore).mockResolvedValueOnce({
      error: "Invalid filter",
      status: 400,
    } as unknown as Awaited<ReturnType<typeof getThreatScore>>);

    render(await ThreatScoreSSR({ searchParams: {} }));

    expect(screen.queryByTestId("overview-context")).not.toBeInTheDocument();
  });

  it("publishes a zero critical count when the field is absent", async () => {
    vi.mocked(getThreatScore).mockResolvedValueOnce({
      data: [
        {
          attributes: {
            overall_score: "70",
            score_delta: null,
            section_scores: {},
          },
        },
      ],
    } as unknown as Awaited<ReturnType<typeof getThreatScore>>);

    render(await ThreatScoreSSR({ searchParams: {} }));

    expect(screen.getByTestId("overview-context")).toHaveTextContent(
      '"criticalRequirementsCount":0',
    );
  });
});
