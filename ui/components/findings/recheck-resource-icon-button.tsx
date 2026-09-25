"use client";

import { RefreshCw } from "lucide-react";
import type { MouseEvent } from "react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import { usePartialScanStore } from "@/store";
import type { PartialScanTarget } from "@/types/partial-scans";

import { RECHECK_RESOURCE_LABEL } from "./recheck-resource-action-item";
import { usePartialScanTarget } from "./use-partial-scan-target";

interface RecheckResourceIconButtonProps {
  target: Partial<PartialScanTarget> | null | undefined;
  className?: string;
}

// A quiet affordance beside "last seen": muted until the row is hovered or
// the button focused, so it reads as a hint rather than a call to action.
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
        <button
          type="button"
          aria-label={RECHECK_RESOURCE_LABEL}
          onClick={handleClick}
          className={cn(
            "text-text-neutral-tertiary inline-flex size-5 shrink-0 items-center justify-center rounded-md transition-colors",
            "group-hover:text-text-neutral-secondary hover:text-text-neutral-primary focus-visible:text-text-neutral-primary",
            "focus-visible:ring-ring/50 focus-visible:ring-2 focus-visible:outline-none",
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
