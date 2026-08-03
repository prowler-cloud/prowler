import { create } from "zustand";
import { persist } from "zustand/middleware";

interface ComplianceWatchlistViewState {
  /** When true, every compliance surface renders only the pinned frameworks. */
  showOnlyWatchlist: boolean;
  setShowOnlyWatchlist: (value: boolean) => void;
}

/**
 * View-level state of the compliance watchlist filter.
 *
 * Deliberately not in the URL: the Multiple Scans and Single Scan tabs are two
 * separate navigations, and a search param would reset on every tab switch —
 * the filter is a viewing preference, not part of the shareable view. Persisted
 * so it survives reloads, mirroring how "Include muted findings" behaves for
 * the whole session.
 *
 * Off by default: a viewer who has never touched the filter sees the full
 * catalog, so a framework can never silently go missing.
 *
 * Read it through `useShowOnlyWatchlist`, never with a bare selector: the
 * compliance surfaces are server-rendered with the default, and `persist` reads
 * localStorage as the store is created.
 */
export const useComplianceWatchlistViewStore =
  create<ComplianceWatchlistViewState>()(
    persist(
      (set) => ({
        showOnlyWatchlist: false,
        setShowOnlyWatchlist: (value) => set({ showOnlyWatchlist: value }),
      }),
      {
        name: "compliance-watchlist-view",
        version: 1,
        // Only the flag: the setter is rebuilt on every load, and persisting it
        // would freeze today's implementation into localStorage.
        partialize: (state) => ({
          showOnlyWatchlist: state.showOnlyWatchlist,
        }),
      },
    ),
  );
