import { beforeEach, describe, expect, it, vi } from "vitest";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { makeComplianceCatalogEntry } from "@/test-utils/compliance-watchlist";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";

import { loadCrossProviderFrameworks } from "../cross-provider-catalog";
import { loadComplianceWatchlistContext } from "../watchlist-context";

// Reads the session through next-auth, unimportable here; tested separately.
vi.mock("../watchlist-context", () => ({
  loadComplianceWatchlistContext: vi.fn(),
}));

const universalEntry = (
  complianceId: string,
  overrides: Partial<ComplianceCatalogEntry> = {},
) =>
  makeComplianceCatalogEntry({
    complianceId,
    providerType: "*",
    framework: complianceId.toUpperCase(),
    ...overrides,
  });

const withCatalog = (entries: ComplianceCatalogEntry[], unavailable = false) =>
  vi.mocked(loadComplianceWatchlistContext).mockResolvedValue({
    entries,
    eligibleProviderTypes: ["aws", "azure", "gcp"],
    canManage: true,
    unavailable,
  });

describe("loadCrossProviderFrameworks", () => {
  beforeEach(() => {
    vi.mocked(loadComplianceWatchlistContext).mockReset();
  });

  it("maps the universal catalog entries onto framework cards", async () => {
    withCatalog([
      universalEntry("dora_2022_2554", {
        framework: "DORA",
        version: "2022/2554",
        description: "Digital Operational Resilience Act.",
      }),
    ]);

    const { frameworks, unavailable } = await loadCrossProviderFrameworks();

    expect(unavailable).toBe(false);
    expect(frameworks).toEqual([
      {
        complianceId: "dora_2022_2554",
        title: "DORA",
        version: "2022/2554",
        description: "Digital Operational Resilience Act.",
        providerTypes: ["aws", "azure", "gcp"],
      },
    ]);
  });

  it("includes a framework registered outside the SDK", async () => {
    withCatalog([
      universalEntry("acme_1.0", { framework: "ACME" }),
      universalEntry("csa_ccm_4.0", { framework: "CSA-CCM" }),
    ]);

    const { frameworks } = await loadCrossProviderFrameworks();

    expect(frameworks.map((entry) => entry.complianceId)).toContain("acme_1.0");
  });

  it("keeps externally registered provider types", async () => {
    // Dropping them here would leave the framework with no way to be pinned.
    withCatalog([
      universalEntry("acme_1.0", {
        framework: "ACME",
        providerTypes: ["aws", "totally-external-provider"],
      }),
    ]);

    const { frameworks } = await loadCrossProviderFrameworks();

    expect(frameworks[0].providerTypes).toEqual([
      "aws",
      "totally-external-provider",
    ]);
  });

  it("drops provider-scoped entries", async () => {
    withCatalog([
      universalEntry("csa_ccm_4.0", { framework: "CSA-CCM" }),
      makeComplianceCatalogEntry({
        complianceId: "cis_1.4_aws",
        providerType: "aws",
        framework: "CIS",
      }),
    ]);

    const { frameworks } = await loadCrossProviderFrameworks();

    expect(frameworks.map((entry) => entry.complianceId)).toEqual([
      "csa_ccm_4.0",
    ]);
  });

  it("drops a framework with no title, which has no route to link to", async () => {
    withCatalog([
      universalEntry("csa_ccm_4.0", { framework: "CSA-CCM" }),
      universalEntry("nameless_1.0", { framework: "  " }),
    ]);

    const { frameworks } = await loadCrossProviderFrameworks();

    expect(frameworks.map((entry) => entry.complianceId)).toEqual([
      "csa_ccm_4.0",
    ]);
  });

  it("orders the cards by title", async () => {
    withCatalog([
      universalEntry("dora_2022_2554", { framework: "DORA" }),
      universalEntry("cmmc_2.0", { framework: "CMMC" }),
    ]);

    const { frameworks } = await loadCrossProviderFrameworks();

    expect(frameworks.map((entry) => entry.title)).toEqual(["CMMC", "DORA"]);
  });

  it("titles the shipped frameworks so their icon resolves", async () => {
    withCatalog([
      universalEntry("csa_ccm_4.0", { framework: "CSA-CCM" }),
      universalEntry("cis_controls_8.1", { framework: "CIS-Controls" }),
      universalEntry("dora_2022_2554", { framework: "DORA" }),
      universalEntry("cmmc_2.0", { framework: "CMMC" }),
    ]);

    const { frameworks } = await loadCrossProviderFrameworks();
    for (const entry of frameworks) {
      expect(getComplianceIcon(entry.title), entry.title).not.toBeNull();
    }
  });

  it("returns nothing when the catalog is empty", async () => {
    withCatalog([]);

    expect(await loadCrossProviderFrameworks()).toEqual({
      frameworks: [],
      unavailable: false,
    });
  });

  it("reports a catalog that could not be read", async () => {
    withCatalog([], true);

    expect(await loadCrossProviderFrameworks()).toEqual({
      frameworks: [],
      unavailable: true,
    });
  });
});
