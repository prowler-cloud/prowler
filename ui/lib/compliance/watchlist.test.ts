import { describe, expect, it } from "vitest";

import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";
import {
  UNIVERSAL_PROVIDER_TYPE,
  WATCHLIST_SCOPE,
} from "@/types/compliance-watchlist";

import {
  buildWatchlistIndex,
  computeWatchlistDiff,
  exceedsWatchlistBulkLimit,
  isFrameworkPinned,
  MAX_WATCHLIST_BULK,
  resolveWatchlistEntryId,
  watchlistKey,
} from "./watchlist";

const entry = (
  overrides: Partial<ComplianceCatalogEntry> &
    Pick<ComplianceCatalogEntry, "complianceId" | "providerType">,
): ComplianceCatalogEntry => ({
  id: `${overrides.providerType}:${overrides.complianceId}`,
  scope:
    overrides.providerType === UNIVERSAL_PROVIDER_TYPE
      ? WATCHLIST_SCOPE.UNIVERSAL
      : WATCHLIST_SCOPE.PROVIDER,
  providerTypes: [overrides.providerType],
  framework: "CIS",
  name: "CIS",
  version: "1.4",
  description: "",
  totalRequirements: 10,
  requirementsPassed: 5,
  requirementsFailed: 5,
  requirementsManual: 0,
  score: 50,
  hasData: true,
  inWatchlist: false,
  watchlistEntryId: null,
  ...overrides,
});

describe("watchlistKey", () => {
  it("keys a framework by provider type and compliance id, never by name", () => {
    expect(
      watchlistKey({ complianceId: "cis_1.4_aws", providerType: "aws" }),
    ).toBe("aws:cis_1.4_aws");
  });

  it("keeps the same compliance id under different provider types apart", () => {
    const aws = watchlistKey({
      complianceId: "dora_2022_2554",
      providerType: "aws",
    });
    const azure = watchlistKey({
      complianceId: "dora_2022_2554",
      providerType: "azure",
    });

    expect(aws).not.toBe(azure);
  });
});

describe("buildWatchlistIndex", () => {
  it("indexes catalog entries by their (provider_type, compliance_id) key", () => {
    const index = buildWatchlistIndex([
      entry({ complianceId: "cis_1.4_aws", providerType: "aws" }),
      entry({ complianceId: "cis_1.4_aws", providerType: "azure" }),
    ]);

    expect(index.size).toBe(2);
    expect(index.get("azure:cis_1.4_aws")?.providerType).toBe("azure");
  });

  it("returns an empty index for an empty catalog", () => {
    expect(buildWatchlistIndex([]).size).toBe(0);
  });
});

describe("isFrameworkPinned", () => {
  const index = buildWatchlistIndex([
    entry({
      complianceId: "cis_1.4_aws",
      providerType: "aws",
      inWatchlist: true,
      watchlistEntryId: "entry-1",
    }),
    entry({ complianceId: "gdpr_aws", providerType: "aws" }),
  ]);

  it("reports a pinned framework", () => {
    expect(
      isFrameworkPinned(index, {
        complianceId: "cis_1.4_aws",
        providerType: "aws",
      }),
    ).toBe(true);
  });

  it("reports an unpinned framework", () => {
    expect(
      isFrameworkPinned(index, {
        complianceId: "gdpr_aws",
        providerType: "aws",
      }),
    ).toBe(false);
  });

  it("treats a framework missing from the catalog as unpinned", () => {
    expect(
      isFrameworkPinned(index, {
        complianceId: "unknown",
        providerType: "aws",
      }),
    ).toBe(false);
  });

  describe("universal frameworks", () => {
    const universalIndex = buildWatchlistIndex([
      entry({
        complianceId: "csa_ccm_4.0",
        providerType: UNIVERSAL_PROVIDER_TYPE,
        inWatchlist: true,
        watchlistEntryId: "entry-universal",
      }),
      entry({ complianceId: "cis_1.4_aws", providerType: "aws" }),
    ]);

    it("resolves the single card from a concrete provider type", () => {
      expect(
        isFrameworkPinned(universalIndex, {
          complianceId: "csa_ccm_4.0",
          providerType: "aws",
        }),
      ).toBe(true);
    });

    it("resolves a legacy per-provider slug onto the same card", () => {
      // Scans predating the universal frameworks stored `csa_ccm_4.0_aws`. The
      // API peels that suffix on write, so a card reading it literally showed
      // as unpinned no matter how often it was pinned.
      expect(
        isFrameworkPinned(universalIndex, {
          complianceId: "csa_ccm_4.0_aws",
          providerType: "aws",
        }),
      ).toBe(true);
      expect(
        resolveWatchlistEntryId(universalIndex, {
          complianceId: "csa_ccm_4.0_aws",
          providerType: "aws",
        }),
      ).toBe("entry-universal");
    });

    it("does not peel the suffix of a provider-scoped framework", () => {
      // `cis_1.4_aws` ends in its own provider type but is not universal, so
      // peeling it must not resolve `cis_1.4` onto some other card.
      expect(
        resolveWatchlistEntryId(universalIndex, {
          complianceId: "cis_1.4_aws",
          providerType: "aws",
        }),
      ).toBeNull();
    });
  });

  it("resolves the delete target without a lookup round trip", () => {
    expect(
      resolveWatchlistEntryId(index, {
        complianceId: "cis_1.4_aws",
        providerType: "aws",
      }),
    ).toBe("entry-1");
    expect(
      resolveWatchlistEntryId(index, {
        complianceId: "gdpr_aws",
        providerType: "aws",
      }),
    ).toBeNull();
  });
});

describe("computeWatchlistDiff", () => {
  const initial = [
    { complianceId: "cis_1.4_aws", providerType: "aws" },
    { complianceId: "dora_2022_2554", providerType: "azure" },
  ];

  it("returns an empty diff when nothing changed", () => {
    expect(computeWatchlistDiff(initial, initial)).toEqual({
      add: [],
      remove: [],
    });
  });

  it("collects only the newly selected frameworks under add", () => {
    const diff = computeWatchlistDiff(initial, [
      ...initial,
      { complianceId: "gdpr_aws", providerType: "aws" },
    ]);

    expect(diff.add).toEqual([
      { complianceId: "gdpr_aws", providerType: "aws" },
    ]);
    expect(diff.remove).toEqual([]);
  });

  it("collects only the deselected frameworks under remove", () => {
    const diff = computeWatchlistDiff(initial, [
      { complianceId: "cis_1.4_aws", providerType: "aws" },
    ]);

    expect(diff.add).toEqual([]);
    expect(diff.remove).toEqual([
      { complianceId: "dora_2022_2554", providerType: "azure" },
    ]);
  });

  it("computes additions and removals in the same pass", () => {
    const diff = computeWatchlistDiff(initial, [
      { complianceId: "dora_2022_2554", providerType: "azure" },
      { complianceId: "gdpr_aws", providerType: "aws" },
    ]);

    expect(diff.add).toEqual([
      { complianceId: "gdpr_aws", providerType: "aws" },
    ]);
    expect(diff.remove).toEqual([
      { complianceId: "cis_1.4_aws", providerType: "aws" },
    ]);
  });

  it("does not confuse the same compliance id across provider types", () => {
    const diff = computeWatchlistDiff(
      [{ complianceId: "dora_2022_2554", providerType: "aws" }],
      [{ complianceId: "dora_2022_2554", providerType: "azure" }],
    );

    expect(diff.add).toEqual([
      { complianceId: "dora_2022_2554", providerType: "azure" },
    ]);
    expect(diff.remove).toEqual([
      { complianceId: "dora_2022_2554", providerType: "aws" },
    ]);
  });

  it("deduplicates repeated targets on both sides", () => {
    const diff = computeWatchlistDiff(
      [],
      [
        { complianceId: "gdpr_aws", providerType: "aws" },
        { complianceId: "gdpr_aws", providerType: "aws" },
      ],
    );

    expect(diff.add).toHaveLength(1);
  });
});

describe("exceedsWatchlistBulkLimit", () => {
  const target = (index: number) => ({
    complianceId: `framework_${index}`,
    providerType: "aws",
  });

  it("accepts a diff at the limit", () => {
    const add = Array.from({ length: MAX_WATCHLIST_BULK }, (_, i) => target(i));

    expect(exceedsWatchlistBulkLimit({ add, remove: [] })).toBe(false);
  });

  it("rejects a diff whose add and remove lists together exceed the limit", () => {
    const add = Array.from({ length: MAX_WATCHLIST_BULK }, (_, i) => target(i));

    expect(exceedsWatchlistBulkLimit({ add, remove: [target(9999)] })).toBe(
      true,
    );
  });
});
