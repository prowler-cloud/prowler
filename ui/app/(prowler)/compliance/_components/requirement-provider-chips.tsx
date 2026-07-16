"use client";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/shadcn/table/status-finding-badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { PROVIDER_DISPLAY_NAMES, PROVIDER_TYPES } from "@/types/providers";

import type { ProviderStatusMap } from "../_types";

interface RequirementProviderChipsProps {
  providers: ProviderStatusMap;
}

/** Per-provider status chips shown next to a cross-provider requirement:
 *  each contributing provider's icon paired with its own PASS/FAIL/MANUAL. */
export const RequirementProviderChips = ({
  providers,
}: RequirementProviderChipsProps) => {
  // Iterate the canonical order so chips are stable across requirements.
  const entries = PROVIDER_TYPES.filter((type) => providers[type]);

  return (
    <div className="flex flex-wrap items-center gap-2">
      {entries.map((type) => (
        <Tooltip key={type}>
          <TooltipTrigger asChild>
            <span
              data-testid={`requirement-chip-${type}`}
              className="inline-flex items-center gap-1"
            >
              <ProviderTypeIcon type={type} size={16} />
              <StatusFindingBadge
                status={providers[type] as FindingStatus}
                size="sm"
              />
            </span>
          </TooltipTrigger>
          <TooltipContent>{PROVIDER_DISPLAY_NAMES[type]}</TooltipContent>
        </Tooltip>
      ))}
    </div>
  );
};
