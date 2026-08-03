"use client";

import { Pin } from "lucide-react";
import type { MouseEvent } from "react";
import { useOptimistic, useTransition } from "react";

import {
  addComplianceToWatchlist,
  bulkUpdateComplianceWatchlist,
  removeComplianceFromWatchlist,
} from "@/actions/compliance-watchlist";
import { Button } from "@/components/shadcn/button/button";
import { useToast } from "@/components/shadcn/toast/use-toast";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import type {
  ComplianceWatchlistActionResult,
  ComplianceWatchlistTarget,
  WatchlistPinState,
} from "@/types/compliance-watchlist";
import { WATCHLIST_PIN_STATE } from "@/types/compliance-watchlist";

interface WatchlistToggleProps {
  /**
   * The `(compliance_id, provider_type)` pairs this card maps to — normally
   * exactly one, because the watchlist keys entries the same way the UI draws
   * cards. Universal frameworks (DORA, CSA CCM, CIS Controls) are pinned once
   * under the `*` sentinel rather than once per compatible provider type, so
   * they are no exception. The list survives for callers that legitimately
   * batch several cards.
   */
  targets: ComplianceWatchlistTarget[];
  state: WatchlistPinState;
  /** Watchlist entry id when the card maps to a single pinned pair, so the
   *  removal can use the single-entry DELETE without a lookup. */
  entryId?: string | null;
  className?: string;
}

const LABELS = {
  [WATCHLIST_PIN_STATE.UNPINNED]: "Add to Watchlist",
  [WATCHLIST_PIN_STATE.PINNED]: "Remove From Watchlist",
} as const satisfies Record<WatchlistPinState, string>;

/**
 * Shared per-card watchlist action for all three compliance surfaces (Single
 * Scan, Across provider types, Across providers).
 *
 * Pinned state is binary: every card maps to one watchlist entry, so the same
 * framework toggled from any surface hits the same row and all three views
 * agree. Callers resolve the target through the catalog
 * (`resolveWatchlistTarget`) so a universal framework is written under `*`,
 * never under the provider type the surface happens to be showing.
 */
export const WatchlistToggle = ({
  targets,
  state,
  entryId,
  className,
}: WatchlistToggleProps) => {
  const { toast } = useToast();
  const [isPending, startTransition] = useTransition();
  // useOptimistic (not useState) so the override is scoped to the transition:
  // it reverts by itself when the action settles, whether the server accepted
  // the change or rejected it.
  const [optimisticState, setOptimisticState] = useOptimistic(state);

  const isPinned = optimisticState === WATCHLIST_PIN_STATE.PINNED;
  const label = LABELS[optimisticState];

  const mutate = (): Promise<ComplianceWatchlistActionResult> => {
    if (isPinned) {
      // Single pinned pair with a known entry id: cheapest possible removal.
      if (targets.length === 1 && entryId) {
        return removeComplianceFromWatchlist(entryId);
      }
      return bulkUpdateComplianceWatchlist({ add: [], remove: targets });
    }
    if (targets.length === 1) {
      return addComplianceToWatchlist(targets[0]);
    }
    return bulkUpdateComplianceWatchlist({ add: targets, remove: [] });
  };

  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    // The surrounding card is itself a button that navigates to the framework
    // detail; toggling must never trigger that navigation.
    event.stopPropagation();
    if (targets.length === 0 || isPending) return;

    startTransition(async () => {
      setOptimisticState(
        isPinned ? WATCHLIST_PIN_STATE.UNPINNED : WATCHLIST_PIN_STATE.PINNED,
      );
      const result = await mutate();

      if (result.error) {
        toast({
          variant: "destructive",
          title: "Oops! Something went wrong",
          description: result.error,
        });
        return;
      }

      toast({
        title: "Success!",
        description: isPinned
          ? "The framework was removed from the watchlist."
          : "The framework was added to the watchlist.",
      });
    });
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          // `bare`, not `ghost`: the shared variant already describes this
          // exact control — icon only, no box painted on hover, colour shift
          // instead — and it drops the `disabled:bg-button-disabled` that made
          // a grey rectangle flash while the mutation was in flight.
          variant="bare"
          size="icon-sm"
          type="button"
          data-pin-state={optimisticState}
          // Icon-only: a labelled link stole a whole row on an already dense
          // card. The label survives as the accessible name and the tooltip.
          aria-label="Watchlist"
          // The state itself, so a screen reader announces the change on
          // toggle. A swapped `aria-label` on the focused element does not get
          // announced, so the old label-only approach was silent.
          aria-pressed={isPinned}
          disabled={isPending}
          onClick={handleClick}
          onKeyDown={(event) => event.stopPropagation()}
          className={cn(
            // Pinned reads at full contrast; the destructive tone lands on
            // hover, where the action actually is a removal.
            isPinned &&
              "text-text-neutral-primary hover:text-text-error-primary",
            className,
          )}
        >
          <Pin aria-hidden className={cn(isPinned && "fill-current")} />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
};
