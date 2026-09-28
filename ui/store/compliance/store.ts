import { create } from "zustand";
import { persist } from "zustand/middleware";

interface ComplianceWatchlistViewState {
  showOnlyWatchlist: boolean;
  setShowOnlyWatchlist: (value: boolean) => void;
}

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
        partialize: (state) => ({
          showOnlyWatchlist: state.showOnlyWatchlist,
        }),
      },
    ),
  );
