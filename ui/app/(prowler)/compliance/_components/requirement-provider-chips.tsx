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
import {
  compareProviderTypes,
  getProviderDisplayName,
} from "@/types/providers";

import type { ProviderStatusMap } from "../_types";

import { RequirementStatusSummary } from "./requirement-status-summary";

interface RequirementProviderChipsProps {
  providers: ProviderStatusMap;
}

/** Icon chips are compact, so five fit comfortably (CSA's full provider
 *  set); frameworks like CIS Controls declare up to 14 provider types,
 *  where the row must collapse to the aggregated summary instead. */
const MAX_INLINE_PROVIDER_CHIPS = 5;

/** Per-provider status chips shown next to a cross-provider requirement:
 *  each contributing provider's icon paired with its own PASS/FAIL/MANUAL.
 *  With many provider types, collapses to per-status counts + hover
 *  breakdown. */
export const RequirementProviderChips = ({
  providers,
}: RequirementProviderChipsProps) => {
  // Canonical order so chips are stable across requirements.
  const entries = Object.keys(providers)
    .filter((type) => providers[type])
    .sort(compareProviderTypes);

  if (entries.length > MAX_INLINE_PROVIDER_CHIPS) {
    return (
      <RequirementStatusSummary
        entries={entries.map((type) => ({
          key: type,
          label: getProviderDisplayName(type),
          icon: <ProviderTypeIcon type={type} size={14} />,
          status: providers[type]!,
        }))}
      />
    );
  }

  return (
    // shrink-0: same rationale as RequirementAccountChips — keep the chips
    // on one line and let the row title truncate instead.
    <div className="flex shrink-0 items-center justify-end gap-2">
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
          <TooltipContent>{getProviderDisplayName(type)}</TooltipContent>
        </Tooltip>
      ))}
    </div>
  );
};
