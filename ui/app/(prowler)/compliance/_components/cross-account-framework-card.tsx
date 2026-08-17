"use client";

import { useRouter, useSearchParams } from "next/navigation";

import { WatchlistToggle } from "@/components/compliance/watchlist/watchlist-toggle";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { formatComplianceFrameworkTitle } from "@/lib/compliance/framework-title";
import type { WatchlistPinState } from "@/types/compliance-watchlist";
import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";

import { buildCrossAccountDetailHref } from "../_lib/cross-account-frameworks";
import type { CrossAccountFrameworkEntry } from "../_types";

import { AggregatedFrameworkCard } from "./aggregated-framework-card";

interface CrossAccountFrameworkCardProps extends CrossAccountFrameworkEntry {
  /** Pinned state of this `(compliance_id, provider_type)` pair. A regular
   *  framework belongs to a single provider type, so it is never partial. */
  watchlistState?: WatchlistPinState;
  watchlistEntryId?: string | null;
  /** MANAGE_SCANS. Without it the toggle is not rendered. */
  canManageWatchlist?: boolean;
}

/**
 * Card for a regular per-provider framework in the Cross-Provider tab's
 * "across accounts" section. Deliberately lightweight — no roll-up numbers:
 * the section only enumerates which frameworks can be viewed across accounts
 * (computing every framework's N-account aggregation up front would be one
 * heavy roll-up call per card). The detail computes the real aggregation.
 */
export const CrossAccountFrameworkCard = ({
  complianceId,
  title,
  version,
  providerType,
  accountCount,
  watchlistState,
  watchlistEntryId,
  canManageWatchlist = false,
}: CrossAccountFrameworkCardProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const formattedTitle = formatComplianceFrameworkTitle(title, version);

  const navigateToDetail = () => {
    router.push(
      buildCrossAccountDetailHref(
        { complianceId, title, version, providerType },
        Object.fromEntries(searchParams.entries()),
      ),
    );
  };

  return (
    <AggregatedFrameworkCard
      frameworkTitle={title}
      formattedTitle={formattedTitle}
      ariaLabel={`${formattedTitle} across ${PROVIDER_DISPLAY_NAMES[providerType]} providers`}
      onActivate={navigateToDetail}
      actions={
        watchlistState && canManageWatchlist ? (
          <WatchlistToggle
            target={{ complianceId, providerType }}
            state={watchlistState}
            entryId={watchlistEntryId}
          />
        ) : undefined
      }
      subtitle={
        <small className="text-text-neutral-secondary truncate text-xs">
          View across providers
        </small>
      }
    >
      <div className="flex items-center justify-between gap-3">
        <span className="inline-flex items-center gap-1.5 text-xs">
          <ProviderTypeIcon type={providerType} size={16} />
          {PROVIDER_DISPLAY_NAMES[providerType]}
        </span>
        <span className="text-text-neutral-secondary text-xs whitespace-nowrap">
          {accountCount} providers
        </span>
      </div>
    </AggregatedFrameworkCard>
  );
};
