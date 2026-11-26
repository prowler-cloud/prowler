"use client";

import { LockKeyhole } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
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
import { useCloudUpgradeStore } from "@/store";
import {
  CLOUD_UPGRADE_SURFACE,
  type CloudUpgradeFeature,
  type CloudUpgradeSurface,
} from "@/types/cloud-upgrade";

interface PremiumTagProps {
  compact?: boolean;
}

// For rows that are already clickable, where a nested button is not allowed.
export function PremiumTag({ compact = false }: PremiumTagProps) {
  return (
    <Badge variant="cloud" size={compact ? "sm" : "default"}>
      <LockKeyhole aria-hidden="true" className="size-3" />
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
}: PremiumBadgeProps) {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="bare"
          size="link-xs"
          aria-label={`${compact ? PREMIUM_BADGE_COMPACT_LABEL : PREMIUM_BADGE_LABEL}: ${PREMIUM_BADGE_TOOLTIP}`}
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            openCloudUpgrade(feature, event.currentTarget, surface);
          }}
        >
          <PremiumTag compact={compact} />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{PREMIUM_BADGE_TOOLTIP}</TooltipContent>
    </Tooltip>
  );
}
