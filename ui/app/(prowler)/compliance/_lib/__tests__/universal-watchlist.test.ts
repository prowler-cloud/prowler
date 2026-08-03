import { describe, expect, it } from "vitest";

import { buildWatchlistIndex } from "@/lib/compliance/watchlist";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";
import {
  UNIVERSAL_PROVIDER_TYPE,
  WATCHLIST_PIN_STATE,
  WATCHLIST_SCOPE,
} from "@/types/compliance-watchlist";

import { resolveUniversalWatchlistState } from "../universal-watchlist";

const COMPLIANCE_ID = "dora_2022_2554";

/** The catalog emits one card for a universal framework, keyed by `*`. */
const universalEntry = (
  inWatchlist: boolean,
  providerTypes = ["aws", "azure", "gcp"],
): ComplianceCatalogEntry => ({
  id: `${UNIVERSAL_PROVIDER_TYPE}:${COMPLIANCE_ID}`,
  complianceId: COMPLIANCE_ID,
  providerType: UNIVERSAL_PROVIDER_TYPE,
  scope: WATCHLIST_SCOPE.UNIVERSAL,
  providerTypes,
  framework: "DORA",
  name: "DORA",
  version: "2022/2554",
  description: "",
  totalRequirements: 10,
  requirementsPassed: 5,
  requirementsFailed: 5,
  requirementsManual: 0,
  score: 50,
  hasData: true,
  inWatchlist,
  watchlistEntryId: inWatchlist ? "entry-universal" : null,
});

const resolve = (
  entries: ComplianceCatalogEntry[],
  eligibleProviderTypes: string[],
  compatibleProviders = ["aws", "azure", "gcp"],
) =>
  resolveUniversalWatchlistState({
    complianceId: COMPLIANCE_ID,
    compatibleProviders,
    eligibleProviderTypes,
    catalogIndex: buildWatchlistIndex(entries),
  });

describe("resolveUniversalWatchlistState", () => {
  it("is pinned when the universal card is pinned", () => {
    const result = resolve([universalEntry(true)], ["aws", "azure", "gcp"]);

    expect(result.state).toBe(WATCHLIST_PIN_STATE.PINNED);
    expect(result.entryId).toBe("entry-universal");
  });

  it("is unpinned when the universal card is not pinned", () => {
    const result = resolve([universalEntry(false)], ["aws", "azure", "gcp"]);

    expect(result.state).toBe(WATCHLIST_PIN_STATE.UNPINNED);
    expect(result.entryId).toBeNull();
  });

  it("targets the single `*` row, never one pair per provider type", () => {
    // The fan-out this replaces produced one target per eligible type, which
    // the API then collapsed onto this same row — and a diff carrying both
    // shapes added and removed it in one call.
    const result = resolve([universalEntry(false)], ["aws", "azure"]);

    expect(result.targets).toEqual([
      { complianceId: COMPLIANCE_ID, providerType: UNIVERSAL_PROVIDER_TYPE },
    ]);
  });

  it("stays pinned when the tenant has only some of the compatible types", () => {
    // One entry covers every type, so there is no partial state to fall into.
    const result = resolve([universalEntry(true, ["aws"])], ["aws"]);

    expect(result.state).toBe(WATCHLIST_PIN_STATE.PINNED);
    expect(result.eligibleCount).toBe(1);
  });

  it("reports no targets when none of the compatible types is eligible", () => {
    const result = resolve([], []);

    expect(result.targets).toEqual([]);
    expect(result.state).toBe(WATCHLIST_PIN_STATE.UNPINNED);
    expect(result.eligibleCount).toBe(0);
  });

  it("treats a framework missing from the catalog as unpinned", () => {
    const result = resolve([], ["aws"]);

    expect(result.state).toBe(WATCHLIST_PIN_STATE.UNPINNED);
    expect(result.eligibleCount).toBe(1);
  });
});
