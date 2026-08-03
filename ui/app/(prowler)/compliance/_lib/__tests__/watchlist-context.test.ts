import { beforeEach, describe, expect, it, vi } from "vitest";

const { getComplianceCatalogMock, authMock, isCloudMock } = vi.hoisted(() => ({
  getComplianceCatalogMock: vi.fn(),
  authMock: vi.fn(),
  isCloudMock: vi.fn(),
}));

vi.mock("@/actions/compliance-watchlist", () => ({
  getComplianceCatalog: getComplianceCatalogMock,
}));

vi.mock("@/auth.config", () => ({
  auth: authMock,
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
}));

import {
  EMPTY_WATCHLIST_CONTEXT,
  loadComplianceWatchlistContext,
} from "../watchlist-context";

const catalog = {
  entries: [
    {
      id: "aws:cis_1.4_aws",
      complianceId: "cis_1.4_aws",
      providerType: "aws",
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
      inWatchlist: true,
      watchlistEntryId: "entry-1",
    },
  ],
  meta: {
    totalEntries: 1,
    watchlistCount: 1,
    eligibleProviderTypes: ["aws", "azure"],
  },
};

beforeEach(() => {
  getComplianceCatalogMock.mockResolvedValue(catalog);
  authMock.mockResolvedValue({
    user: { permissions: { manage_scans: true } },
  });
});

describe("loadComplianceWatchlistContext in OSS", () => {
  beforeEach(() => isCloudMock.mockReturnValue(false));

  it("returns the empty context", async () => {
    expect(await loadComplianceWatchlistContext()).toEqual(
      EMPTY_WATCHLIST_CONTEXT,
    );
  });

  it("fires no catalog request at all", async () => {
    await loadComplianceWatchlistContext();

    expect(getComplianceCatalogMock).not.toHaveBeenCalled();
    expect(authMock).not.toHaveBeenCalled();
  });
});

describe("loadComplianceWatchlistContext in Cloud", () => {
  beforeEach(() => isCloudMock.mockReturnValue(true));

  it("exposes the catalog entries and eligible provider types", async () => {
    const context = await loadComplianceWatchlistContext();

    expect(context.entries).toHaveLength(1);
    expect(context.eligibleProviderTypes).toEqual(["aws", "azure"]);
  });

  it("forwards the provider type narrowing to the catalog", async () => {
    await loadComplianceWatchlistContext({ providerTypes: ["aws"] });

    expect(getComplianceCatalogMock).toHaveBeenCalledWith({
      providerTypes: ["aws"],
    });
  });

  it("grants curation with the manage scans permission", async () => {
    expect((await loadComplianceWatchlistContext()).canManage).toBe(true);
  });

  it("denies curation without the manage scans permission", async () => {
    authMock.mockResolvedValue({
      user: { permissions: { manage_scans: false } },
    });

    expect((await loadComplianceWatchlistContext()).canManage).toBe(false);
  });

  it("denies curation when there is no session", async () => {
    authMock.mockResolvedValue(null);

    expect((await loadComplianceWatchlistContext()).canManage).toBe(false);
  });
});
