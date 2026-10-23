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
}

// Beside "last seen": always green and pulsing, so the re-check is noticed.
// It is an action, not a notification, so it never settles into a seen state.
export function RecheckResourceIconButton({
  target,
  className,
}: RecheckResourceIconButtonProps) {
  const resolvedTarget = usePartialScanTarget(target);
  const openPartialScan = usePartialScanStore((state) => state.openPartialScan);

  if (!resolvedTarget) return null;

  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    // The row itself opens the detail drawer on click.
    event.stopPropagation();
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
          onClick={handleClick}
          className={cn(
            "text-button-primary hover:text-button-primary active:text-button-primary size-5 shrink-0 rounded-md motion-safe:animate-pulse",
            "hover:[animation-play-state:paused] focus-visible:[animation-play-state:paused]",
            className,
          )}
        >
          <RefreshCw className="size-3.5" aria-hidden />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{RECHECK_RESOURCE_LABEL}</TooltipContent>
    </Tooltip>
  );
}
