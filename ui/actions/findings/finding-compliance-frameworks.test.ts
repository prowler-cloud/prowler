import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, isCloudMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  isCloudMock: vi.fn(() => true),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
}));

import { getFindingComplianceFrameworks } from "./finding-compliance-frameworks";

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/vnd.api+json" },
  });

const framework = (attributes: Record<string, unknown>) => ({
  type: "finding-compliance-frameworks",
  id: `${attributes.provider_type}:${attributes.compliance_id}`,
  attributes: {
    compliance_id: "cis_1.4_aws",
    provider_type: "aws",
    scope: "provider",
    framework: "CIS",
    name: "CIS",
    version: "1.4",
    in_watchlist: true,
    ...attributes,
  },
});

const lastFetchUrl = (): URL => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  return new URL(String(call[0]));
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockResolvedValue(jsonResponse({ data: [] }));
  getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  isCloudMock.mockReturnValue(true);
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("getFindingComplianceFrameworks", () => {
  it("rejects a null options payload before fetching", async () => {
    const result = await getFindingComplianceFrameworks(
      "finding-1",
      null as never,
    );

    expect(result).toEqual({ frameworks: [], unavailable: true });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("asks only for the watchlisted frameworks when told to", async () => {
    await getFindingComplianceFrameworks("finding-1", { inWatchlist: true });

    const url = lastFetchUrl();
    expect(url.pathname).toBe(
      "/api/v1/findings/finding-1/compliance-frameworks",
    );
    expect(url.searchParams.get("filter[in_watchlist]")).toBe("true");
  });

  it("omits the filter by default, so the endpoint keeps returning every framework", async () => {
    await getFindingComplianceFrameworks("finding-1");

    expect(lastFetchUrl().searchParams.has("filter[in_watchlist]")).toBe(false);
  });

  it("adapts the response, keeping the compliance id that makes navigation exact", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        data: [
          framework({}),
          framework({
            compliance_id: "dora_2022_2554",
            provider_type: "*",
            scope: "universal",
            framework: "DORA",
          }),
        ],
      }),
    );

    const result = await getFindingComplianceFrameworks("finding-1", {
      inWatchlist: true,
    });

    expect(result.frameworks).toHaveLength(2);
    expect(result.unavailable).toBe(false);
    expect(result.frameworks[0].complianceId).toBe("cis_1.4_aws");
    expect(result.frameworks[0].scope).toBe("provider");
    expect(result.frameworks[1].scope).toBe("universal");
    expect(result.frameworks[1].providerType).toBe("*");
  });

  it("reports the endpoint as unavailable when it answers an error", async () => {
    // The endpoint is Cloud-only, so a self-hosted install 404s here. The
    // caller has to tell that apart from an empty watchlist, or the strip
    // disappears from every finding.
    fetchMock.mockResolvedValue(jsonResponse({ errors: [] }, 404));

    expect(await getFindingComplianceFrameworks("finding-1")).toEqual({
      frameworks: [],
      unavailable: true,
    });
  });

  it("reports an empty watchlist as a real answer, not as unavailable", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ data: [] }));

    expect(
      await getFindingComplianceFrameworks("finding-1", { inWatchlist: true }),
    ).toEqual({ frameworks: [], unavailable: false });
  });

  it("does not call the API without a finding id", async () => {
    expect(await getFindingComplianceFrameworks("")).toEqual({
      frameworks: [],
      unavailable: false,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not call the API at all off Cloud", async () => {
    // The endpoint only exists in Cloud, and the drawer asks once per finding
    // opened — so this is a request that can only ever 404, on every open.
    isCloudMock.mockReturnValue(false);

    expect(await getFindingComplianceFrameworks("finding-1")).toEqual({
      frameworks: [],
      // `unavailable`, so the caller still falls back to the check's own
      // framework names instead of dropping the strip.
      unavailable: true,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
