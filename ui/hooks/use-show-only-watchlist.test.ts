import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { useShowOnlyWatchlist } from "@/hooks/use-show-only-watchlist";
import { useComplianceWatchlistViewStore } from "@/store/compliance/store";

describe("useShowOnlyWatchlist", () => {
  beforeEach(() => {
    localStorage.clear();
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: false });
  });

  it("reads the stored value only after mount, so the first render matches the server", async () => {
    // The compliance surfaces are server-rendered with the filter off, so a
    // stored `true` reaching the first client render would be a hydration
    // mismatch.
    localStorage.setItem(
      "compliance-watchlist-view",
      JSON.stringify({ state: { showOnlyWatchlist: true }, version: 1 }),
    );
    useComplianceWatchlistViewStore.setState({ showOnlyWatchlist: true });

    // Every render is recorded: the value only settles after mount, and
    // asserting on the final one would pass even without the deferral.
    const rendered: boolean[] = [];
    renderHook(() => {
      rendered.push(useShowOnlyWatchlist());
    });

    expect(rendered[0]).toBe(false);
    await waitFor(() => expect(rendered.at(-1)).toBe(true));
  });
});
