import { describe, expect, it } from "vitest";

import { makeComplianceCatalogEntry } from "@/test-utils/compliance-watchlist";
import { UNIVERSAL_PROVIDER_TYPE } from "@/types/compliance-watchlist";

import {
  buildWatchlistIndex,
  computeWatchlistDiff,
  exceedsWatchlistBulkLimit,
  formatWatchlistBulkSummary,
  isFrameworkPinned,
  MAX_WATCHLIST_BULK,
  resolveWatchlistEntryId,
  resolveWatchlistTarget,
} from "./watchlist";

describe("watchlist catalog lookup", () => {
  const index = buildWatchlistIndex([
    makeComplianceCatalogEntry({
      complianceId: "cis_1.4_aws",
      providerType: "aws",
      inWatchlist: true,
      watchlistEntryId: "entry-aws",
    }),
    makeComplianceCatalogEntry({
      complianceId: "gdpr_aws",
      providerType: "aws",
    }),
  ]);

  it.each([
    ["cis_1.4_aws", true],
    ["gdpr_aws", false],
    ["unknown", false],
  ])("resolves %s pinned state", (complianceId, expected) => {
    expect(
      isFrameworkPinned(index, { complianceId, providerType: "aws" }),
    ).toBe(expected);
  });

  it("returns the entry id only for catalog rows that have one", () => {
    expect(
      resolveWatchlistEntryId(index, {
        complianceId: "cis_1.4_aws",
        providerType: "aws",
      }),
    ).toBe("entry-aws");
    expect(
      resolveWatchlistEntryId(index, {
        complianceId: "gdpr_aws",
        providerType: "aws",
      }),
    ).toBeNull();
  });
});

describe("universal framework lookup", () => {
  const index = buildWatchlistIndex([
    makeComplianceCatalogEntry({
      complianceId: "csa_ccm_4.0",
      providerType: UNIVERSAL_PROVIDER_TYPE,
      inWatchlist: true,
      watchlistEntryId: "entry-universal",
    }),
    makeComplianceCatalogEntry({
      complianceId: "cis_1.4_aws",
      providerType: "aws",
    }),
  ]);

  it("resolves concrete and legacy ids onto the universal row", () => {
    expect(
      isFrameworkPinned(index, {
        complianceId: "csa_ccm_4.0",
        providerType: "aws",
      }),
    ).toBe(true);
    expect(
      resolveWatchlistEntryId(index, {
        complianceId: "csa_ccm_4.0_aws",
        providerType: "aws",
      }),
    ).toBe("entry-universal");
  });

  it("does not peel a provider-scoped framework suffix", () => {
    expect(
      resolveWatchlistEntryId(index, {
        complianceId: "cis_1.4_aws",
        providerType: "aws",
      }),
    ).toBeNull();
  });

  it("prefers an exact provider row over a colliding universal row", () => {
    const collision = buildWatchlistIndex([
      makeComplianceCatalogEntry({
        complianceId: "shared_id",
        providerType: UNIVERSAL_PROVIDER_TYPE,
        inWatchlist: true,
      }),
      makeComplianceCatalogEntry({
        complianceId: "shared_id",
        providerType: "aws",
      }),
    ]);
    const target = { complianceId: "shared_id", providerType: "aws" };

    expect(isFrameworkPinned(collision, target)).toBe(false);
    expect(resolveWatchlistTarget(collision, target)).toEqual(target);
  });

  it("normalizes writes to the universal target", () => {
    expect(
      resolveWatchlistTarget(index, {
        complianceId: "csa_ccm_4.0",
        providerType: "aws",
      }),
    ).toEqual({
      complianceId: "csa_ccm_4.0",
      providerType: UNIVERSAL_PROVIDER_TYPE,
    });
  });
});

describe("computeWatchlistDiff", () => {
  const aws = { complianceId: "cis_1.4_aws", providerType: "aws" };
  const azure = { complianceId: "dora_2022_2554", providerType: "azure" };
  const gdpr = { complianceId: "gdpr_aws", providerType: "aws" };

  it("returns an empty diff when nothing changed", () => {
    expect(computeWatchlistDiff([aws, azure], [aws, azure])).toEqual({
      add: [],
      remove: [],
    });
  });

  it("computes additions and removals together", () => {
    expect(computeWatchlistDiff([aws, azure], [azure, gdpr])).toEqual({
      add: [gdpr],
      remove: [aws],
    });
  });

  it("keeps identical compliance ids from different providers separate", () => {
    const source = { complianceId: "dora", providerType: "aws" };
    const target = { complianceId: "dora", providerType: "azure" };

    expect(computeWatchlistDiff([source], [target])).toEqual({
      add: [target],
      remove: [source],
    });
  });

  it("deduplicates repeated targets", () => {
    expect(computeWatchlistDiff([], [gdpr, gdpr]).add).toEqual([gdpr]);
  });
});

describe("watchlist bulk boundaries", () => {
  const targets = Array.from({ length: MAX_WATCHLIST_BULK }, (_, index) => ({
    complianceId: `framework_${index}`,
    providerType: "aws",
  }));

  it.each([
    [{ add: targets, remove: [] }, false],
    [
      {
        add: targets,
        remove: [{ complianceId: "overflow", providerType: "aws" }],
      },
      true,
    ],
  ])("detects whether a diff exceeds the limit", (diff, expected) => {
    expect(exceedsWatchlistBulkLimit(diff)).toBe(expected);
  });
});

describe("formatWatchlistBulkSummary", () => {
  it.each([
    [{ added: 2, removed: 1 }, "2 added · 1 removed"],
    [{ added: 3, removed: 0 }, "3 added"],
    [{ added: 0, removed: 4 }, "4 removed"],
    [{ added: 0, removed: 0 }, "No changes"],
  ])("formats the applied changes", (summary, expected) => {
    expect(formatWatchlistBulkSummary(summary)).toBe(expected);
  });
});
