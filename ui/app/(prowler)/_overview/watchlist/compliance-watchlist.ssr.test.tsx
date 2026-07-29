import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ComplianceWatchlistSSR } from "./compliance-watchlist.ssr";

vi.mock("@/actions/overview/compliance-watchlist", () => ({
  getComplianceWatchlist: vi.fn(async () => ({})),
  adaptComplianceWatchlistResponse: vi.fn(() => [
    {
      id: "1",
      complianceId: "cis_1.5_aws",
      label: "CIS AWS 1.5",
      icon: null,
      score: 45,
    },
    {
      id: "2",
      complianceId: "nis2_azure",
      label: "NIS2 Azure",
      icon: null,
      score: 82,
    },
    {
      id: "3",
      complianceId: "ens_rd2022_aws",
      label: "ENS RD2022",
      icon: null,
      score: 30,
    },
    {
      id: "4",
      complianceId: "prowler_threatscore_aws",
      label: "ThreatScore",
      icon: null,
      score: 10,
    },
  ]),
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="watchlist-context">{JSON.stringify(item)}</output>
  ),
}));

vi.mock("./_components/compliance-watchlist", () => ({
  ComplianceWatchlist: () => <div>watchlist</div>,
}));

describe("ComplianceWatchlistSSR", () => {
  it("publishes the two lowest-scoring frameworks as Lighthouse context", async () => {
    render(await ComplianceWatchlistSSR({ searchParams: {} }));

    const contexts = screen.getAllByTestId("watchlist-context");
    expect(contexts).toHaveLength(2);
    expect(contexts[0]).toHaveTextContent('"framework":"ENS RD2022"');
    expect(contexts[0]).toHaveTextContent('"score":30');
    expect(contexts[0]).toHaveTextContent('"scopeKey":"overview:/"');
    expect(contexts[1]).toHaveTextContent('"framework":"CIS AWS 1.5"');
    expect(contexts[1]).toHaveTextContent('"score":45');
  });
});
