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
import { usePartialScanStore } from "@/store";
import type { PartialScanTarget } from "@/types/partial-scans";

import { RECHECK_RESOURCE_LABEL } from "./recheck-resource-action-item";

interface RecheckResourceIconButtonProps {
  target: Partial<PartialScanTarget> | null | undefined;
  className?: string;
  disabledReason?: string;
}

// Beside "last seen", using the shared icon-button and disabled states.
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
        <span
          className={className}
          tabIndex={disabledReason ? 0 : undefined}
          onClick={(event) => event.stopPropagation()}
        >
          <Button
            type="button"
            variant="bare"
            size="icon-xs"
            aria-label={RECHECK_RESOURCE_LABEL}
            disabled={Boolean(disabledReason)}
            onClick={handleClick}
          >
            <RefreshCw aria-hidden />
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {disabledReason ?? RECHECK_RESOURCE_LABEL}
      </TooltipContent>
    </Tooltip>
  );
}
