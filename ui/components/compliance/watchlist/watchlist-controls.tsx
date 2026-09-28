import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";

import { WatchlistFilterToggle } from "./watchlist-filter-toggle";
import { WatchlistMultiSelect } from "./watchlist-multi-select";

interface WatchlistControlsProps {
  entries: ComplianceCatalogEntry[];
  canManageWatchlist: boolean;
}

export const WatchlistControls = ({
  entries,
  canManageWatchlist,
}: WatchlistControlsProps) => {
  if (entries.length === 0) return null;

  return (
    <div className="flex shrink-0 items-center gap-4">
      <WatchlistFilterToggle />
      {canManageWatchlist && (
        <div className="w-56">
          <WatchlistMultiSelect entries={entries} />
        </div>
      )}
    </div>
  );
};
