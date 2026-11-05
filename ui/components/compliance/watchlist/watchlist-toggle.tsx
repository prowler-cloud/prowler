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
  target: ComplianceWatchlistTarget;
  state: WatchlistPinState;
  entryId?: string | null;
}

const LABELS = {
  [WATCHLIST_PIN_STATE.UNPINNED]: "Add to Watchlist",
  [WATCHLIST_PIN_STATE.PINNED]: "Remove From Watchlist",
} as const satisfies Record<WatchlistPinState, string>;

export const WatchlistToggle = ({
  target,
  state,
  entryId,
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
      if (entryId) {
        return removeComplianceFromWatchlist(entryId);
      }
      return bulkUpdateComplianceWatchlist({ add: [], remove: [target] });
    }
    return addComplianceToWatchlist(target);
  };

  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    if (isPending) return;

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
          variant="bare"
          size="icon-sm"
          type="button"
          data-pin-state={optimisticState}
          aria-label="Watchlist"
          aria-pressed={isPinned}
          disabled={isPending}
          onClick={handleClick}
          onKeyDown={(event) => event.stopPropagation()}
        >
          <Pin aria-hidden className={cn(isPinned && "fill-current")} />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
};
