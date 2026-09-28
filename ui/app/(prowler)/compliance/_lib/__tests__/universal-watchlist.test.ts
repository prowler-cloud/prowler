import { describe, expect, it } from "vitest";

import { buildWatchlistIndex } from "@/lib/compliance/watchlist";
import { makeComplianceCatalogEntry } from "@/test-utils/compliance-watchlist";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";
import {
  UNIVERSAL_PROVIDER_TYPE,
  WATCHLIST_PIN_STATE,
} from "@/types/compliance-watchlist";

import { resolveUniversalWatchlistState } from "../universal-watchlist";

const COMPLIANCE_ID = "dora_2022_2554";

const universalEntry = (
  inWatchlist: boolean,
  providerTypes = ["aws", "azure", "gcp"],
): ComplianceCatalogEntry =>
  makeComplianceCatalogEntry({
    complianceId: COMPLIANCE_ID,
    providerType: UNIVERSAL_PROVIDER_TYPE,
    providerTypes,
    framework: "DORA",
    name: "DORA",
    version: "2022/2554",
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

  it("targets one universal row", () => {
    const result = resolve([universalEntry(false)], ["aws", "azure"]);

    expect(result.target).toEqual({
      complianceId: COMPLIANCE_ID,
      providerType: UNIVERSAL_PROVIDER_TYPE,
    });
  });

  it("stays pinned when the tenant has only some of the compatible types", () => {
    // One entry covers every type, so there is no partial state to fall into.
    const result = resolve([universalEntry(true, ["aws"])], ["aws"]);

    expect(result.state).toBe(WATCHLIST_PIN_STATE.PINNED);
    expect(result.eligibleCount).toBe(1);
  });

  it("is not pinnable when no compatible provider is eligible", () => {
    const result = resolve([], []);

    expect(result.target).toBeNull();
    expect(result.state).toBe(WATCHLIST_PIN_STATE.UNPINNED);
    expect(result.eligibleCount).toBe(0);
  });

  it("keeps a pinned card removable after the last compatible type is offboarded", () => {
    const result = resolve([universalEntry(true)], []);

    expect(result.state).toBe(WATCHLIST_PIN_STATE.PINNED);
    expect(result.eligibleCount).toBe(0);
    expect(result.target).toEqual({
      complianceId: COMPLIANCE_ID,
      providerType: UNIVERSAL_PROVIDER_TYPE,
    });
    expect(result.entryId).toBe("entry-universal");
  });
});
