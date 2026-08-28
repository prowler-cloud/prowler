"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { ComplianceCard } from "@/components/compliance/compliance-card";
import { ComplianceFrameworkGrid } from "@/components/compliance/compliance-framework-grid";
import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { OnboardingTrigger, PageReady } from "@/components/onboarding";
import { DataTableSearch } from "@/components/shadcn/table/data-table-search";
import { useShowOnlyWatchlist } from "@/hooks/use-show-only-watchlist";
import { buildComplianceDetailPath } from "@/lib/compliance/compliance-detail-url";
import {
  buildWatchlistIndex,
  isFrameworkPinned,
  resolveWatchlistEntryId,
} from "@/lib/compliance/watchlist";
import {
  LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE,
  LIGHTHOUSE_CONTEXT_CONTRIBUTOR_LIMIT,
} from "@/lib/lighthouse/context/constants";
import { buildComplianceContext } from "@/lib/lighthouse/context/contributions";
import { getFlowById } from "@/lib/onboarding";
import { createViewComplianceTourStepHandlers } from "@/lib/tours/view-compliance.tour";
import type { ComplianceOverviewData } from "@/types/compliance";
import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";
import { WATCHLIST_PIN_STATE } from "@/types/compliance-watchlist";
import type { ScanEntity } from "@/types/scans";

import { WatchlistEmptyState } from "./watchlist/watchlist-empty-state";
import { WatchlistToggle } from "./watchlist/watchlist-toggle";

const viewComplianceFlow = getFlowById("view-compliance")!;

// Module-level so the identity is stable: `configOverrides` is an effect dependency in
// `useDriverTour`, and a fresh object per keystroke would tear the tour down mid-typing.
const VIEW_COMPLIANCE_TOUR_CONFIG = {
  // Last step opens the first card (see createViewComplianceTourStepHandlers).
  doneBtnText: "Open Compliance",
};

interface ComplianceOverviewGridProps {
  frameworks: ComplianceOverviewData[];
  scanId: string;
  selectedScan?: ScanEntity;
  latestCisIds?: ReadonlySet<string>;
  catalogEntries?: ComplianceCatalogEntry[];
  providerType?: string;
  canManageWatchlist?: boolean;
}

export const ComplianceOverviewGrid = ({
  frameworks,
  scanId,
  selectedScan,
  latestCisIds,
  catalogEntries,
  providerType,
  canManageWatchlist = false,
}: ComplianceOverviewGridProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [searchTerm, setSearchTerm] = useState("");
  const showOnlyWatchlist = useShowOnlyWatchlist();

  const filteredFrameworks = frameworks.filter((compliance) =>
    compliance.attributes.framework
      .toLowerCase()
      .includes(searchTerm.toLowerCase()),
  );

  const catalogIndex = buildWatchlistIndex(catalogEntries ?? []);
  const watchlistEnabled =
    Boolean(providerType) && (catalogEntries?.length ?? 0) > 0;

  const isPinned = (complianceId: string) =>
    watchlistEnabled &&
    isFrameworkPinned(catalogIndex, {
      complianceId,
      providerType: providerType!,
    });

  // Counted before the search, so a term that matches nothing pinned does not
  // make the empty state claim the organization has pinned nothing.
  const pinnedTotal = watchlistEnabled
    ? frameworks.filter((compliance) => isPinned(compliance.id)).length
    : 0;

  const filterToWatchlist = watchlistEnabled && showOnlyWatchlist;
  const visibleFrameworks = filterToWatchlist
    ? filteredFrameworks.filter((compliance) => isPinned(compliance.id))
    : filteredFrameworks;
  const tourAnchorId = visibleFrameworks[0]?.id;

  const resetSearch = () => {
    setSearchTerm("");
    // Clearing the search does not bring the anchor back while the persisted
    // watchlist filter is on and nothing is pinned: the grid renders the empty
    // state instead, so the tour has to skip the step rather than wait for a
    // selector that never mounts.
    return filterToWatchlist ? pinnedTotal > 0 : frameworks.length > 0;
  };

  const openFirstFramework = () => {
    // The fallback covers a search that filtered every card away — never the
    // watchlist filter, where opening a hidden framework would contradict the
    // list the user is looking at.
    const first =
      visibleFrameworks[0] ?? (filterToWatchlist ? undefined : frameworks[0]);
    if (!first) return;
    router.push(
      buildComplianceDetailPath({
        title: first.attributes.framework,
        complianceId: first.id,
        version: first.attributes.version,
        scanId,
        regionFilter: searchParams.get("filter[region__in]"),
      }),
    );
  };

  const renderGrid = (items: ComplianceOverviewData[]) => (
    <ComplianceFrameworkGrid>
      {items.map((compliance) => {
        const { attributes, id } = compliance;
        const { framework, version, requirements_passed, total_requirements } =
          attributes;

        return (
          <div
            key={id}
            {...(id === tourAnchorId
              ? { "data-tour-id": "view-compliance-frameworks" }
              : {})}
            className="h-full [&>*]:h-full"
          >
            <ComplianceCard
              title={framework}
              version={version}
              passingRequirements={requirements_passed}
              totalRequirements={total_requirements}
              prevPassingRequirements={requirements_passed}
              prevTotalRequirements={total_requirements}
              scanId={scanId}
              complianceId={id}
              id={id}
              selectedScan={selectedScan}
              isLatestCisForProvider={latestCisIds?.has(id) ?? false}
              watchlistAction={
                watchlistEnabled && canManageWatchlist ? (
                  <WatchlistToggle
                    target={{ complianceId: id, providerType: providerType! }}
                    state={
                      isPinned(id)
                        ? WATCHLIST_PIN_STATE.PINNED
                        : WATCHLIST_PIN_STATE.UNPINNED
                    }
                    entryId={resolveWatchlistEntryId(catalogIndex, {
                      complianceId: id,
                      providerType: providerType!,
                    })}
                  />
                ) : undefined
              }
            />
          </div>
        );
      })}
    </ComplianceFrameworkGrid>
  );

  return (
    <>
      {filteredFrameworks
        .slice(0, LIGHTHOUSE_CONTEXT_CONTRIBUTOR_LIMIT.AFTER_PAGE)
        .map(({ attributes, id }) => (
          <LighthouseContextContributor
            key={`compliance-${id}-${attributes.requirements_passed}-${attributes.requirements_failed}`}
            contributorId={`compliance-${id}`}
            item={buildComplianceContext({
              pathname: "/compliance",
              id,
              framework: attributes.framework,
              version: attributes.version,
              scanId,
              providerUid: selectedScan?.providerInfo.uid,
              mode: LIGHTHOUSE_COMPLIANCE_CONTEXT_MODE.PER_SCAN,
              region: searchParams.get("filter[region__in]") ?? undefined,
              passed: attributes.requirements_passed,
              failed: attributes.requirements_failed,
              total: attributes.total_requirements,
            })}
          />
        ))}
      {/* Suspense required: OnboardingTrigger reads useSearchParams */}
      <Suspense fallback={null}>
        <OnboardingTrigger
          flow={viewComplianceFlow}
          stepHandlers={createViewComplianceTourStepHandlers({
            resetSearch,
            openFirstFramework,
          })}
          configOverrides={VIEW_COMPLIANCE_TOUR_CONFIG}
        />
      </Suspense>
      {/* Signals the navbar that this route's data has loaded (enables the replay icon). */}
      <PageReady />
      <div className="flex items-center justify-between gap-4">
        <div data-tour-id="view-compliance-search">
          <DataTableSearch
            controlledValue={searchTerm}
            onSearchChange={setSearchTerm}
            placeholder="Search frameworks..."
          />
        </div>
        <span className="text-text-neutral-secondary shrink-0 text-sm">
          {visibleFrameworks.length.toLocaleString()} Total Entries
        </span>
      </div>
      {filterToWatchlist && visibleFrameworks.length === 0 ? (
        <WatchlistEmptyState
          message={
            // A search term is the likelier culprit than an uncurated
            // watchlist, so it gets its own copy instead of telling someone
            // who has already pinned frameworks that they have pinned none.
            pinnedTotal > 0
              ? "No pinned framework matches your search."
              : undefined
          }
        />
      ) : (
        renderGrid(visibleFrameworks)
      )}
    </>
  );
};
