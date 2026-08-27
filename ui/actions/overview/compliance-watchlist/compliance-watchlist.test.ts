import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

// Stubbed out because the real helper reaches into next-auth and Sentry, which
// this suite has no interest in: every assertion is about the request URL.
vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: async (response: Response) => response.json(),
}));

import { getComplianceWatchlist } from "./compliance-watchlist";

const emptyResponse = () =>
  new Response(JSON.stringify({ data: [] }), {
    status: 200,
    headers: { "Content-Type": "application/vnd.api+json" },
  });

const lastFetchUrl = (): URL => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  return new URL(String(call[0]));
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockResolvedValue(emptyResponse());
  getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
});

describe("getComplianceWatchlist", () => {
  it("rejects a null Server Action payload before fetching", async () => {
    const result = await getComplianceWatchlist(null as never);

    expect(result).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("narrows the response to the watchlist when asked to", async () => {
    await getComplianceWatchlist({ inWatchlist: true });

    expect(lastFetchUrl().searchParams.get("filter[in_watchlist]")).toBe(
      "true",
    );
  });

  it("omits the filter by default, leaving the endpoint's own behavior intact", async () => {
    // The API treats the parameter as opt-in, so a caller that wants the full
    // framework ranking must not send it at all — `false` would be a filter.
    await getComplianceWatchlist();

    expect(lastFetchUrl().searchParams.has("filter[in_watchlist]")).toBe(false);
  });

  it("keeps the provider filters alongside the watchlist one", async () => {
    await getComplianceWatchlist({
      filters: { "filter[provider_type]": "aws" },
      inWatchlist: true,
    });

    const url = lastFetchUrl();
    expect(url.searchParams.get("filter[provider_type]")).toBe("aws");
    expect(url.searchParams.get("filter[in_watchlist]")).toBe("true");
  });
});
