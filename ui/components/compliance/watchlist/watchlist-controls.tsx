import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";

import { WatchlistFilterToggle } from "./watchlist-filter-toggle";
import { WatchlistMultiSelect } from "./watchlist-multi-select";

interface WatchlistControlsProps {
  /** Full catalog, deliberately not narrowed to the active tab: the watchlist
   *  is tenant-wide and both tabs edit the same list. */
  entries: ComplianceCatalogEntry[];
  /** MANAGE_SCANS. Without it the editor is not rendered (rather than
   *  rendered disabled), because writing would 403 — but the filter stays, so
   *  a read-only member can still narrow the view to what the team curated. */
  canManageWatchlist: boolean;
}

/**
 * The watchlist's controls, rendered on the compliance tab bar so they sit
 * above both tabs at once. Filtering and editing are shared state: switching
 * tabs keeps the filter, and a framework pinned here shows up pinned on the
 * other tab.
 *
 * Renders nothing when the catalog is empty — OSS has no catalog endpoint at
 * all, so this is what keeps the feature Cloud-only without an `isCloud()`
 * check on the client. A server component itself: both controls are their own
 * client islands, so the tab bar does not ship this wrapper to the browser.
 */
export const WatchlistControls = ({
  entries,
  canManageWatchlist,
}: WatchlistControlsProps) => {
  if (entries.length === 0) return null;

  return (
    <div className="flex shrink-0 items-center gap-4">
      <WatchlistFilterToggle />
      {canManageWatchlist && (
        // The selector's trigger is `w-full` like every other one in the app,
        // so its width belongs to this container rather than to a call-site
        // override on the shared control.
        <div className="w-56">
          <WatchlistMultiSelect entries={entries} />
        </div>
      )}
    </div>
  );
};
