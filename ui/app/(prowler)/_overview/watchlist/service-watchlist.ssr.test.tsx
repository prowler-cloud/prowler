import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { getServicesOverview } from "@/actions/overview";

import { ServiceWatchlistSSR } from "./service-watchlist.ssr";

vi.mock("@/actions/overview", () => ({
  getServicesOverview: vi.fn(async () => ({
    data: [
      {
        type: "services-overview",
        id: "iam",
        attributes: { total: 50, fail: 12, muted: 0, pass: 38 },
      },
      {
        type: "services-overview",
        id: "s3",
        attributes: { total: 120, fail: 34, muted: 2, pass: 84 },
      },
    ],
  })),
}));

vi.mock("@/components/lighthouse/context-contributor", () => ({
  LighthouseContextContributor: ({ item }: { item: unknown }) => (
    <output data-testid="service-context">{JSON.stringify(item)}</output>
  ),
}));

vi.mock("./_components/service-watchlist", () => ({
  ServiceWatchlist: () => <div>watchlist</div>,
}));

describe("ServiceWatchlistSSR", () => {
  it("publishes the service with most failing findings as Lighthouse context", async () => {
    render(await ServiceWatchlistSSR({ searchParams: {} }));

    const context = screen.getByTestId("service-context");
    expect(context).toHaveTextContent('"id":"service-s3"');
    expect(context).toHaveTextContent('"scopeKey":"overview:/"');
    expect(context).toHaveTextContent('"failedFindingsCount":34');
    expect(context).toHaveTextContent('"total":120');
  });

  it("publishes no service context when no service has failing findings", async () => {
    vi.mocked(getServicesOverview).mockResolvedValueOnce({
      data: [
        {
          type: "services-overview",
          id: "iam",
          attributes: { total: 50, fail: 0, muted: 0, pass: 50 },
        },
      ],
    } as unknown as Awaited<ReturnType<typeof getServicesOverview>>);

    render(await ServiceWatchlistSSR({ searchParams: {} }));

    expect(screen.queryByTestId("service-context")).not.toBeInTheDocument();
  });

  it("publishes no service context on a 4xx response", async () => {
    // handleApiResponse resolves truthy {error, status} objects for 4xx.
    vi.mocked(getServicesOverview).mockResolvedValueOnce({
      error: "Invalid filter",
      status: 400,
    } as unknown as Awaited<ReturnType<typeof getServicesOverview>>);

    render(await ServiceWatchlistSSR({ searchParams: {} }));

    expect(screen.queryByTestId("service-context")).not.toBeInTheDocument();
  });
});
