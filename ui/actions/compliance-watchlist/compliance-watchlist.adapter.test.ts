import { describe, expect, it } from "vitest";

import {
  adaptCatalogResponse,
  adaptWatchlistBulkSummary,
  mergeCatalogPages,
} from "./compliance-watchlist.adapter";
import type {
  ComplianceCatalogEntryAttributes,
  ComplianceCatalogResponse,
} from "./compliance-watchlist.types";

const catalogPage = (
  overrides: Partial<ComplianceCatalogResponse> = {},
): ComplianceCatalogResponse => ({
  data: [
    {
      type: "compliance-catalog-entries",
      id: "aws:cis_1.4_aws",
      attributes: {
        compliance_id: "cis_1.4_aws",
        provider_type: "aws",
        scope: "provider",
        provider_types: ["aws"],
        framework: "CIS",
        name: "CIS Amazon Web Services Foundations Benchmark",
        version: "1.4",
        description: "desc",
        total_requirements: 60,
        requirements_passed: 30,
        requirements_failed: 20,
        requirements_manual: 10,
        score: 50,
        has_data: true,
        in_watchlist: true,
        watchlist_entry_id: "entry-1",
      },
    },
  ],
  meta: {
    pagination: { page: 1, pages: 1, count: 1 },
    total_entries: 42,
    watchlist_count: 6,
    eligible_provider_types: ["aws", "azure"],
  },
  ...overrides,
});

describe("adaptCatalogResponse", () => {
  it("maps a catalog entry onto the UI shape", () => {
    const { entries } = adaptCatalogResponse(catalogPage());

    expect(entries[0]).toEqual({
      id: "aws:cis_1.4_aws",
      complianceId: "cis_1.4_aws",
      providerType: "aws",
      scope: "provider",
      providerTypes: ["aws"],
      framework: "CIS",
      name: "CIS Amazon Web Services Foundations Benchmark",
      version: "1.4",
      description: "desc",
      totalRequirements: 60,
      requirementsPassed: 30,
      requirementsFailed: 20,
      requirementsManual: 10,
      score: 50,
      hasData: true,
      inWatchlist: true,
      watchlistEntryId: "entry-1",
    });
  });

  it("maps a universal card onto the `*` key it is pinned under", () => {
    const response = catalogPage();
    const attributes = response.data![0].attributes;
    attributes.compliance_id = "dora_2022_2554";
    attributes.provider_type = "*";
    attributes.scope = "universal";
    attributes.provider_types = ["aws", "azure", "gcp"];
    response.data![0].id = "*:dora_2022_2554";

    const { entries } = adaptCatalogResponse(response);

    expect(entries[0].providerType).toBe("*");
    expect(entries[0].scope).toBe("universal");
    expect(entries[0].providerTypes).toEqual(["aws", "azure", "gcp"]);
  });

  it("falls back to a provider-scoped card when the API omits the scope", () => {
    // An older API has no `scope`/`provider_types`; reading those cards as
    // provider-scoped keeps them keyed exactly as they were before.
    const response = catalogPage();
    const attributes = response.data![0]
      .attributes as Partial<ComplianceCatalogEntryAttributes>;
    delete attributes.scope;
    delete attributes.provider_types;

    const { entries } = adaptCatalogResponse(response);

    expect(entries[0].scope).toBe("provider");
    expect(entries[0].providerTypes).toEqual(["aws"]);
  });

  it("keeps a never-scanned framework's null score instead of coercing it to 0", () => {
    const response = catalogPage();
    response.data![0].attributes.score = null;
    response.data![0].attributes.has_data = false;

    const { entries } = adaptCatalogResponse(response);

    expect(entries[0].score).toBeNull();
    expect(entries[0].hasData).toBe(false);
  });

  it("reads the counters from root meta, not from the page length", () => {
    const { meta } = adaptCatalogResponse(catalogPage());

    expect(meta.totalEntries).toBe(42);
    expect(meta.watchlistCount).toBe(6);
    expect(meta.eligibleProviderTypes).toEqual(["aws", "azure"]);
  });

  it("degrades to an empty catalog when the response has no data", () => {
    const { entries, meta } = adaptCatalogResponse({});

    expect(entries).toEqual([]);
    expect(meta).toEqual({
      totalEntries: 0,
      watchlistCount: 0,
      eligibleProviderTypes: [],
    });
  });
});

describe("mergeCatalogPages", () => {
  it("concatenates entries across pages and keeps the first page's meta", () => {
    const first = adaptCatalogResponse(catalogPage());
    const second = adaptCatalogResponse(
      catalogPage({
        data: [
          {
            ...catalogPage().data![0],
            id: "azure:cis_2.0_azure",
            attributes: {
              ...catalogPage().data![0].attributes,
              compliance_id: "cis_2.0_azure",
              provider_type: "azure",
            },
          },
        ],
        meta: {
          pagination: { page: 2, pages: 2, count: 2 },
          total_entries: 0,
          watchlist_count: 0,
          eligible_provider_types: [],
        },
      }),
    );

    const merged = mergeCatalogPages([first, second]);

    expect(merged.entries).toHaveLength(2);
    expect(merged.meta.totalEntries).toBe(42);
  });

  it("returns an empty catalog when no page loaded", () => {
    expect(mergeCatalogPages([])).toEqual({
      entries: [],
      meta: { totalEntries: 0, watchlistCount: 0, eligibleProviderTypes: [] },
    });
  });
});

describe("adaptWatchlistBulkSummary", () => {
  it("maps the bulk root meta", () => {
    expect(
      adaptWatchlistBulkSummary({
        meta: {
          added: 3,
          already_present: 1,
          removed: 2,
          not_present: 0,
          watchlist_count: 8,
        },
      }),
    ).toEqual({
      added: 3,
      alreadyPresent: 1,
      removed: 2,
      notPresent: 0,
      watchlistCount: 8,
    });
  });

  it("defaults every counter when the meta is missing", () => {
    expect(adaptWatchlistBulkSummary({})).toEqual({
      added: 0,
      alreadyPresent: 0,
      removed: 0,
      notPresent: 0,
      watchlistCount: 0,
    });
  });
});
