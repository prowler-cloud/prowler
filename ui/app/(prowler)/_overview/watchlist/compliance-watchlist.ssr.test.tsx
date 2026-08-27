import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ComplianceWatchlistSSR } from "./compliance-watchlist.ssr";

const { getComplianceWatchlistMock, isCloudMock } = vi.hoisted(() => ({
  getComplianceWatchlistMock: vi.fn(async () => ({})),
  isCloudMock: vi.fn(() => true),
}));

vi.mock("@/actions/overview/compliance-watchlist", () => ({
  getComplianceWatchlist: getComplianceWatchlistMock,
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

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="watchlist-context">{JSON.stringify(item)}</output>
  ),
}));

vi.mock("./_components/compliance-watchlist", () => ({
  ComplianceWatchlist: () => <div>watchlist</div>,
}));

describe("ComplianceWatchlistSSR in Cloud", () => {
  beforeEach(() => isCloudMock.mockReturnValue(true));

  it("asks the API for the watchlist only", async () => {
    // Without this the endpoint answers with every framework that has data, and
    // pinning one changes nothing on the overview card.
    render(await ComplianceWatchlistSSR({ searchParams: {} }));

    expect(getComplianceWatchlistMock).toHaveBeenCalledWith(
      expect.objectContaining({ inWatchlist: true }),
    );
  });

  it("publishes the two lowest-scoring frameworks as Lighthouse context", async () => {
    render(await ComplianceWatchlistSSR({ searchParams: {} }));

    const contexts = screen.getAllByTestId("watchlist-context");
    expect(contexts).toHaveLength(2);
    // ThreatScore is no longer dropped: the response only carries frameworks
    // the organization pinned, so hiding one would contradict that choice.
    expect(contexts[0]).toHaveTextContent('"framework":"ThreatScore"');
    expect(contexts[0]).toHaveTextContent('"score":10');
    expect(contexts[0]).toHaveTextContent('"scopeKey":"overview:/"');
    expect(contexts[1]).toHaveTextContent('"framework":"ENS RD2022"');
    expect(contexts[1]).toHaveTextContent('"score":30');
  });
});

describe("ComplianceWatchlistSSR in OSS", () => {
  beforeEach(() => isCloudMock.mockReturnValue(false));

  it("does not send the Cloud-only watchlist filter", async () => {
    // The filter is a Cloud addition to a shared endpoint; sending it where it
    // does not exist is at best ignored and at worst a 400.
    render(await ComplianceWatchlistSSR({ searchParams: {} }));

    expect(getComplianceWatchlistMock).toHaveBeenCalledWith(
      expect.objectContaining({ inWatchlist: false }),
    );
  });

  it("keeps ThreatScore out of the ranking", async () => {
    // Unfiltered the card is a ranking of everything, which is what it always
    // was — and ThreatScore has never belonged in it.
    render(await ComplianceWatchlistSSR({ searchParams: {} }));

    const contexts = screen.getAllByTestId("watchlist-context");
    expect(contexts).toHaveLength(2);
    expect(contexts[0]).toHaveTextContent('"framework":"ENS RD2022"');
    expect(contexts[1]).toHaveTextContent('"framework":"CIS AWS 1.5"');
  });
});
