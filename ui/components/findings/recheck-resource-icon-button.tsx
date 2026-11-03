"use client";

import { RefreshCw } from "lucide-react";
import type { MouseEvent } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { usePartialScanTarget } from "@/hooks/use-partial-scan-target";
import { cn } from "@/lib/utils";
import { usePartialScanStore } from "@/store";
import type { PartialScanTarget } from "@/types/partial-scans";

import { RECHECK_RESOURCE_LABEL } from "./recheck-resource-action-item";

interface RecheckResourceIconButtonProps {
  target: Partial<PartialScanTarget> | null | undefined;
  className?: string;
  disabledReason?: string;
}

// Beside "last seen": green and pulsing when a re-check is available.
// It is an action, not a notification, so it never settles into a seen state.
export function RecheckResourceIconButton({
  target,
  className,
  disabledReason,
}: RecheckResourceIconButtonProps) {
  const resolvedTarget = usePartialScanTarget(target);
  const openPartialScan = usePartialScanStore((state) => state.openPartialScan);

  if (!resolvedTarget) return null;

  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    // The row itself opens the detail drawer on click.
    event.stopPropagation();
    if (disabledReason) return;
    openPartialScan(resolvedTarget);
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="bare"
          size="icon"
          aria-label={RECHECK_RESOURCE_LABEL}
          aria-disabled={Boolean(disabledReason)}
          onClick={handleClick}
          className={cn(
            "size-5 shrink-0 rounded-md",
            disabledReason
              ? "text-text-neutral-tertiary cursor-not-allowed"
              : "text-button-primary hover:text-button-primary active:text-button-primary hover:[animation-play-state:paused] focus-visible:[animation-play-state:paused] motion-safe:animate-pulse",
            className,
          )}
        >
          <RefreshCw className="size-3.5" aria-hidden />
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        {disabledReason ?? RECHECK_RESOURCE_LABEL}
      </TooltipContent>
    </Tooltip>
  );
}
