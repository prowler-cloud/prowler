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
      },
    ),
  );
