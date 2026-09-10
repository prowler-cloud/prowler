import { useComplianceWatchlistViewStore } from "@/store/compliance/store";

import { useStore } from "./use-store";

/**
 * The compliance watchlist filter, read the only way it is safe to read it.
 *
 * The three compliance surfaces are server-rendered with the filter off, while
 * `persist` reads localStorage as the store is created — so a stored `true`
 * would make the first client render disagree with the server's HTML. `useStore`
 * defers the persisted value to after hydration; until then the flag reads as
 * off, which is the same thing the server sent.
 */
export const useShowOnlyWatchlist = (): boolean =>
  useStore(
    useComplianceWatchlistViewStore,
    (state) => state.showOnlyWatchlist,
  ) ?? false;
