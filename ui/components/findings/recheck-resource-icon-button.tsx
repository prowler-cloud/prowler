"use client";

import { RefreshCw } from "lucide-react";
import { type MouseEvent, useState } from "react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { cn } from "@/lib/utils";
import { usePartialScanHintStore, usePartialScanStore } from "@/store";
import type { PartialScanTarget } from "@/types/partial-scans";

import { RECHECK_RESOURCE_LABEL } from "./recheck-resource-action-item";
import { usePartialScanTarget } from "./use-partial-scan-target";

interface RecheckResourceIconButtonProps {
  target: Partial<PartialScanTarget> | null | undefined;
  className?: string;
}

// Beside "last seen". Until the user has re-checked something once it pulses
// green, like the navbar bell with unread updates; afterwards it settles into
// a muted icon that brightens on row hover or focus.
export function RecheckResourceIconButton({
  target,
  className,
}: RecheckResourceIconButtonProps) {
  const resolvedTarget = usePartialScanTarget(target);
  const openPartialScan = usePartialScanStore((state) => state.openPartialScan);
  const hintSeen = usePartialScanHintStore((state) => state.hasSeenRecheckHint);
  const markHintSeen = usePartialScanHintStore(
    (state) => state.markRecheckHintSeen,
  );
  // Client-only gate: SSR and hydration render the calm icon, the persisted
  // store decides after mount.
  const [hintReady, setHintReady] = useState(false);
  useMountEffect(() => setHintReady(true));

  if (!resolvedTarget) return null;

  const attention = hintReady && !hintSeen;

  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    // The row itself opens the detail drawer on click.
    event.stopPropagation();
    markHintSeen();
    openPartialScan(resolvedTarget);
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={RECHECK_RESOURCE_LABEL}
          data-attention={attention ? "true" : undefined}
          onClick={handleClick}
          className={cn(
            "inline-flex size-5 shrink-0 items-center justify-center rounded-md transition-colors",
            "focus-visible:ring-ring/50 focus-visible:ring-2 focus-visible:outline-none",
            attention
              ? "text-button-primary animate-pulse"
              : "text-text-neutral-tertiary group-hover:text-text-neutral-secondary hover:text-text-neutral-primary focus-visible:text-text-neutral-primary",
            className,
          )}
        >
          <RefreshCw className="size-3.5" aria-hidden />
        </button>
      </TooltipTrigger>
      <TooltipContent>{RECHECK_RESOURCE_LABEL}</TooltipContent>
    </Tooltip>
  );
}
