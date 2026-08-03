import { beforeEach, describe, expect, it } from "vitest";

import { useComplianceWatchlistViewStore } from "@/store/compliance/store";

describe("useComplianceWatchlistViewStore", () => {
  beforeEach(() => {
    localStorage.clear();
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: false });
  });

  it("starts off so the full catalog is visible by default", () => {
    expect(useComplianceWatchlistViewStore.getState().showOnlyWatchlist).toBe(
      false,
    );
  });

  it("toggles the filter on and back off", () => {
    // When
    useComplianceWatchlistViewStore.getState().setShowOnlyWatchlist(true);

    // Then
    expect(useComplianceWatchlistViewStore.getState().showOnlyWatchlist).toBe(
      true,
    );

    // When
    useComplianceWatchlistViewStore.getState().setShowOnlyWatchlist(false);

    // Then
    expect(useComplianceWatchlistViewStore.getState().showOnlyWatchlist).toBe(
      false,
    );
  });

  it("persists the filter so it survives a reload", () => {
    // When
    useComplianceWatchlistViewStore.getState().setShowOnlyWatchlist(true);

    // Then
    expect(localStorage.getItem("compliance-watchlist-view")).toContain(
      '"showOnlyWatchlist":true',
    );
  });

  it("persists the flag alone, never the setter", () => {
    useComplianceWatchlistViewStore.getState().setShowOnlyWatchlist(true);

    expect(
      JSON.parse(localStorage.getItem("compliance-watchlist-view") ?? "{}")
        .state,
    ).toEqual({ showOnlyWatchlist: true });
  });
});
