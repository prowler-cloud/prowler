import { beforeEach, describe, expect, it, vi } from "vitest";

import { makeComplianceCatalogEntry } from "@/test-utils/compliance-watchlist";
import type { ComplianceCatalog } from "@/types/compliance-watchlist";

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

const catalog: ComplianceCatalog = {
  entries: [
    makeComplianceCatalogEntry({
      complianceId: "cis_1.4_aws",
      providerType: "aws",
      framework: "CIS",
      name: "CIS",
      version: "1.4",
      inWatchlist: true,
      watchlistEntryId: "entry-1",
    }),
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

  it("returns the empty context without requesting Cloud data", async () => {
    expect(await loadComplianceWatchlistContext()).toEqual(
      EMPTY_WATCHLIST_CONTEXT,
    );
    expect(getComplianceCatalogMock).not.toHaveBeenCalled();
    expect(authMock).not.toHaveBeenCalled();
  });
});

describe("loadComplianceWatchlistContext in Cloud", () => {
  beforeEach(() => isCloudMock.mockReturnValue(true));

  it("exposes catalog data and curation permission", async () => {
    const context = await loadComplianceWatchlistContext();

    expect(context.entries).toHaveLength(1);
    expect(context.eligibleProviderTypes).toEqual(["aws", "azure"]);
    expect(context.canManage).toBe(true);
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

  it("degrades to the empty context when the session lookup rejects", async () => {
    // Every surface awaits this loader, so a rejected `auth()` costs the
    // watchlist affordances, not the compliance data.
    authMock.mockRejectedValue(new Error("session unavailable"));
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});

    expect(await loadComplianceWatchlistContext()).toEqual({
      ...EMPTY_WATCHLIST_CONTEXT,
      unavailable: true,
    });

    consoleError.mockRestore();
  });

  it("normalizes the provider types so an equivalent list hits one cache entry", async () => {
    // `cache()` keys on argument identity, so the memoized call takes a single
    // normalized string: two surfaces asking for the same narrowed catalog in a
    // different order must not fetch it twice.
    await loadComplianceWatchlistContext({
      providerTypes: ["azure", "aws", "aws"],
    });

    expect(getComplianceCatalogMock).toHaveBeenCalledWith({
      providerTypes: ["aws", "azure"],
    });
  });
});
