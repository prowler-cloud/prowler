import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, revalidatePathMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    revalidatePathMock: vi.fn(),
  }),
);

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
}));

import {
  addComplianceToWatchlist,
  bulkUpdateComplianceWatchlist,
  getComplianceCatalog,
  removeComplianceFromWatchlist,
} from "./compliance-watchlist";

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/vnd.api+json" },
  });

const catalogPage = (
  complianceId: string,
  pagination: { page: number; pages: number },
) => ({
  data: [
    {
      type: "compliance-catalog-entries",
      id: `aws:${complianceId}`,
      attributes: {
        compliance_id: complianceId,
        provider_type: "aws",
        framework: "CIS",
        name: "CIS",
        version: "1.4",
        description: "",
        total_requirements: 10,
        requirements_passed: 5,
        requirements_failed: 5,
        requirements_manual: 0,
        score: 50,
        has_data: true,
        in_watchlist: false,
        watchlist_entry_id: null,
      },
    },
  ],
  meta: {
    pagination: { ...pagination, count: pagination.pages },
    total_entries: pagination.pages,
    watchlist_count: 0,
    eligible_provider_types: ["aws"],
  },
});

const lastFetchUrl = (): URL => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  return new URL(String(call[0]));
};

const lastFetchBody = (): unknown => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  return JSON.parse(String(call[1].body));
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("getComplianceCatalog", () => {
  it("rejects a null Server Action payload before fetching", async () => {
    const catalog = await getComplianceCatalog(null as never);

    expect(catalog).toEqual({
      entries: [],
      meta: {
        totalEntries: 0,
        watchlistCount: 0,
        eligibleProviderTypes: [],
      },
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("requests the maximum page size so a whole catalog needs as few calls as possible", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(catalogPage("cis_1.4_aws", { page: 1, pages: 1 })),
    );

    await getComplianceCatalog();

    expect(lastFetchUrl().searchParams.get("page[size]")).toBe("100");
  });

  it("follows every page and returns the merged catalog", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse(catalogPage("cis_1.4_aws", { page: 1, pages: 3 })),
      )
      .mockResolvedValueOnce(
        jsonResponse(catalogPage("gdpr_aws", { page: 2, pages: 3 })),
      )
      .mockResolvedValueOnce(
        jsonResponse(catalogPage("iso27001_aws", { page: 3, pages: 3 })),
      );

    const catalog = await getComplianceCatalog();

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(catalog.entries.map((entry) => entry.complianceId)).toEqual([
      "cis_1.4_aws",
      "gdpr_aws",
      "iso27001_aws",
    ]);
  });

  it("stops after the first page when there is only one", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(catalogPage("cis_1.4_aws", { page: 1, pages: 1 })),
    );

    await getComplianceCatalog();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("narrows the catalog to the requested provider types", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(catalogPage("cis_1.4_aws", { page: 1, pages: 1 })),
    );

    await getComplianceCatalog({ providerTypes: ["aws", "azure"] });

    expect(lastFetchUrl().searchParams.get("filter[provider_type__in]")).toBe(
      "aws,azure",
    );
  });

  it("omits the provider type filter when none is requested", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(catalogPage("cis_1.4_aws", { page: 1, pages: 1 })),
    );

    await getComplianceCatalog({ providerTypes: [] });

    expect(lastFetchUrl().searchParams.has("filter[provider_type__in]")).toBe(
      false,
    );
  });

  it("degrades to an empty catalog when the request fails", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ errors: [] }, 500));

    const catalog = await getComplianceCatalog();

    expect(catalog).toEqual({
      entries: [],
      meta: {
        totalEntries: 0,
        watchlistCount: 0,
        eligibleProviderTypes: [],
      },
    });
  });

  it("degrades to an empty catalog when fetch throws", async () => {
    fetchMock.mockRejectedValue(new Error("network down"));

    const catalog = await getComplianceCatalog();

    expect(catalog.entries).toEqual([]);
  });

  it("keeps the rest of the catalog when a single page fails", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse(catalogPage("cis_1.4_aws", { page: 1, pages: 3 })),
      )
      .mockRejectedValueOnce(new Error("timed out"))
      .mockResolvedValueOnce(
        jsonResponse(catalogPage("iso27001_aws", { page: 3, pages: 3 })),
      );

    const catalog = await getComplianceCatalog();

    expect(catalog.entries.map((entry) => entry.complianceId)).toEqual([
      "cis_1.4_aws",
      "iso27001_aws",
    ]);
  });

  it("bounds how many pages it requests at once", async () => {
    // A page-1 response reporting a large page count would otherwise open one
    // socket per page against an API that re-runs the whole roll-up for each.
    let inFlight = 0;
    let peak = 0;
    fetchMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          inFlight += 1;
          peak = Math.max(peak, inFlight);
          setTimeout(() => {
            inFlight -= 1;
            resolve(
              jsonResponse(catalogPage("cis_1.4_aws", { page: 1, pages: 40 })),
            );
          }, 0);
        }),
    );

    await getComplianceCatalog();

    expect(fetchMock).toHaveBeenCalledTimes(40);
    expect(peak).toBeLessThanOrEqual(5);
  });

  it("bounds every request with a timeout", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(catalogPage("cis_1.4_aws", { page: 1, pages: 1 })),
    );

    await getComplianceCatalog();

    expect(fetchMock.mock.calls.at(-1)?.[1].signal).toBeInstanceOf(AbortSignal);
  });
});

describe("addComplianceToWatchlist", () => {
  it("rejects non-string target fields before fetching", async () => {
    const result = await addComplianceToWatchlist({
      complianceId: 42,
      providerType: "aws",
    } as never);

    expect(result.error).toBeDefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("posts a single JSON:API entry and revalidates the compliance route", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ data: {} }, 201));

    const result = await addComplianceToWatchlist({
      complianceId: "cis_1.4_aws",
      providerType: "aws",
    });

    expect(lastFetchBody()).toEqual({
      data: {
        type: "compliance-watchlist-entries",
        attributes: {
          compliance_id: "cis_1.4_aws",
          provider_type: "aws",
        },
      },
    });
    expect(result.success).toBeDefined();
    expect(revalidatePathMock).toHaveBeenCalledWith("/compliance");
  });

  it("surfaces the API error detail and does not revalidate", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          errors: [
            {
              detail: "The tenant has no provider of type azure.",
              code: "provider_type_not_available",
            },
          ],
        },
        400,
      ),
    );

    const result = await addComplianceToWatchlist({
      complianceId: "cis_1.4_aws",
      providerType: "azure",
    });

    expect(result.error).toContain("azure");
    expect(revalidatePathMock).not.toHaveBeenCalled();
  });

  it("rejects an empty compliance id before hitting the API", async () => {
    const result = await addComplianceToWatchlist({
      complianceId: "",
      providerType: "aws",
    });

    expect(result.error).toBeDefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("removeComplianceFromWatchlist", () => {
  it("deletes the entry by id", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));

    const result = await removeComplianceFromWatchlist(
      "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    );

    expect(lastFetchUrl().pathname).toContain(
      "/compliance-watchlist-entries/3fa85f64-5717-4562-b3fc-2c963f66afa6",
    );
    expect(result.success).toBeDefined();
    expect(revalidatePathMock).toHaveBeenCalledWith("/compliance");
  });

  it("refuses a non-UUID id instead of interpolating it into the URL", async () => {
    const result = await removeComplianceFromWatchlist("../../providers");

    expect(result.error).toBeDefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("bulkUpdateComplianceWatchlist", () => {
  it.each([null, {}, { add: [], remove: null }])(
    "rejects a malformed Server Action diff %# before fetching",
    async (diff) => {
      const result = await bulkUpdateComplianceWatchlist(diff as never);

      expect(result.error).toBeDefined();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("sends one call carrying both lists and reports the meta summary", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        data: [],
        meta: {
          added: 3,
          already_present: 0,
          removed: 1,
          not_present: 0,
          watchlist_count: 8,
        },
      }),
    );

    const result = await bulkUpdateComplianceWatchlist({
      add: [{ complianceId: "cis_1.4_aws", providerType: "aws" }],
      remove: [{ complianceId: "dora_2022_2554", providerType: "azure" }],
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(lastFetchUrl().pathname).toContain(
      "/compliance-watchlist-entries/bulk",
    );
    expect(lastFetchBody()).toEqual({
      data: {
        type: "compliance-watchlist-bulk",
        attributes: {
          add: [{ compliance_id: "cis_1.4_aws", provider_type: "aws" }],
          remove: [{ compliance_id: "dora_2022_2554", provider_type: "azure" }],
        },
      },
    });
    expect(result.summary).toEqual({
      added: 3,
      alreadyPresent: 0,
      removed: 1,
      notPresent: 0,
      watchlistCount: 8,
    });
    expect(result.success).toContain("3 added");
  });

  it("refuses an empty diff without calling the API", async () => {
    const result = await bulkUpdateComplianceWatchlist({
      add: [],
      remove: [],
    });

    expect(result.error).toBeDefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("guards the 200-item limit client side", async () => {
    const add = Array.from({ length: 201 }, (_, index) => ({
      complianceId: `framework_${index}`,
      providerType: "aws",
    }));

    const result = await bulkUpdateComplianceWatchlist({ add, remove: [] });

    expect(result.error).toContain("200");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("surfaces the API error when the bulk call fails", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        { errors: [{ detail: "Nope.", code: "bulk_limit_exceeded" }] },
        400,
      ),
    );

    const result = await bulkUpdateComplianceWatchlist({
      add: [{ complianceId: "cis_1.4_aws", providerType: "aws" }],
      remove: [],
    });

    expect(result.error).toBe("Nope.");
    expect(revalidatePathMock).not.toHaveBeenCalled();
  });
});
