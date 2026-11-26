"use client";

import { LockKeyhole } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  PREMIUM_BADGE_COMPACT_LABEL,
  PREMIUM_BADGE_LABEL,
  PREMIUM_BADGE_TOOLTIP,
} from "@/lib/cloud-upgrade";
import { cn } from "@/lib/utils";
import { useCloudUpgradeStore } from "@/store";
import {
  CLOUD_UPGRADE_SURFACE,
  type CloudUpgradeFeature,
  type CloudUpgradeSurface,
} from "@/types/cloud-upgrade";

interface PremiumTagProps {
  compact?: boolean;
  className?: string;
}

// For rows that are already clickable, where a nested button is not allowed.
export function PremiumTag({ compact = false, className }: PremiumTagProps) {
  return (
    <Badge
      variant="cloud"
      size={compact ? "sm" : "default"}
      className={className}
    >
      <LockKeyhole aria-hidden="true" />
      {compact ? PREMIUM_BADGE_COMPACT_LABEL : PREMIUM_BADGE_LABEL}
    </Badge>
  );
}

interface PremiumBadgeProps extends PremiumTagProps {
  feature: CloudUpgradeFeature;
  surface?: CloudUpgradeSurface;
}

export function PremiumBadge({
  feature,
  surface = CLOUD_UPGRADE_SURFACE.BADGE,
  compact = false,
  className,
}: PremiumBadgeProps) {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={`${compact ? PREMIUM_BADGE_COMPACT_LABEL : PREMIUM_BADGE_LABEL}: ${PREMIUM_BADGE_TOOLTIP}`}
          className={cn(
            "focus-visible:ring-ring/50 inline-flex shrink-0 cursor-pointer rounded-lg focus-visible:ring-[3px] focus-visible:outline-none",
            className,
          )}
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            openCloudUpgrade(feature, event.currentTarget, surface);
          }}
        >
          <PremiumTag compact={compact} />
        </button>
      </TooltipTrigger>
      <TooltipContent>{PREMIUM_BADGE_TOOLTIP}</TooltipContent>
    </Tooltip>
  );
}
