import { beforeEach, describe, expect, it } from "vitest";

import { useComplianceWatchlistViewStore } from "@/store/compliance/store";

describe("useComplianceWatchlistViewStore", () => {
  beforeEach(() => {
    localStorage.clear();
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: false });
  });

  it("persists only the filter value", () => {
    // When
    useComplianceWatchlistViewStore.getState().setShowOnlyWatchlist(true);

    // Then
    expect(
      JSON.parse(localStorage.getItem("compliance-watchlist-view") ?? "{}")
        .state,
    ).toEqual({ showOnlyWatchlist: true });
  });
});
