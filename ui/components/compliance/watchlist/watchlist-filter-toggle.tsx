"use client";

import { Pin } from "lucide-react";

import { Checkbox } from "@/components/shadcn";
import { useShowOnlyWatchlist } from "@/hooks/use-show-only-watchlist";
import { useComplianceWatchlistViewStore } from "@/store";

const CHECKBOX_ID = "show-only-watchlist";

/**
 * Filters every compliance surface down to the pinned frameworks, mirroring
 * "Include muted findings" on the Findings page.
 *
 * The state lives in the store rather than the URL because the two compliance
 * tabs are separate navigations: the filter has to survive a tab switch, and
 * both tabs read the very same flag so a curated view stays curated across
 * them.
 */
export const WatchlistFilterToggle = () => {
  const showOnlyWatchlist = useShowOnlyWatchlist();
  const setShowOnlyWatchlist = useComplianceWatchlistViewStore(
    (state) => state.setShowOnlyWatchlist,
  );

  return (
    // `text-nowrap`: wrapping the label would push the tab bar's height
    // around, and it is short enough that it never needs to.
    <div className="flex items-center gap-2 text-nowrap">
      <Checkbox
        id={CHECKBOX_ID}
        checked={showOnlyWatchlist}
        onCheckedChange={(checked) => setShowOnlyWatchlist(checked === true)}
      />
      <Pin aria-hidden className="text-text-neutral-tertiary size-3 shrink-0" />
      {/* No `aria-label` on the checkbox: it would override this label, and a
          screen reader would then announce something the user cannot see. */}
      <label
        htmlFor={CHECKBOX_ID}
        className="cursor-pointer text-sm leading-none"
      >
        Show only watchlist
      </label>
    </div>
  );
};
