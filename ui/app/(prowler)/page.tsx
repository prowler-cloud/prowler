import { SquareChartGantt } from "lucide-react";
import { Suspense } from "react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { getLighthouseV2Configurations } from "@/app/(prowler)/lighthouse/_actions";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { ProviderGroupSelector } from "@/components/filters/provider-group-selector";
import {
  APP_SIDEBAR_MODE,
  AppSidebarModeSync,
} from "@/components/layout/app-sidebar";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { FeatureFlagGate } from "@/components/shared/feature-flag-gate";
import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import { DOCS_URLS } from "@/lib/external-urls";
import { FEATURE_FLAG } from "@/lib/feature-flags";
import { getSamplePreviewState } from "@/lib/sample-preview/get-sample-preview-state";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";
import { isCloud } from "@/lib/shared/env";
import { SearchParamsProps } from "@/types";

import { OverviewBanner } from "./_overview/_components/overview-banner";
import { OverviewGrid } from "./_overview/_components/overview-grid";
import { OverviewProviderContext } from "./_overview/_components/overview-provider-context";
import { getLighthouseOverviewBannerHref } from "./_overview/_lib/lighthouse-banner";
import { OVERVIEW_BANNER_VARIANT } from "./_overview/_lib/overview-banner";
import {
  AttackSurfaceSkeleton,
  AttackSurfaceSSR,
} from "./_overview/attack-surface";
import { CheckFindingsSSR } from "./_overview/check-findings";
import {
  ExploitabilityChartSkeleton,
  ExploitabilityChartSSR,
  TopIssuesSkeleton,
  TopIssuesSSR,
} from "./_overview/exploitability";
import { GraphsTabsWrapper } from "./_overview/graphs-tabs/graphs-tabs-wrapper";
import { RiskPipelineViewSkeleton } from "./_overview/graphs-tabs/risk-pipeline-view";
import {
  ResourcesInventorySkeleton,
  ResourcesInventorySSR,
} from "./_overview/resources-inventory";
import {
  RiskSeverityChartSkeleton,
  RiskSeverityChartSSR,
} from "./_overview/risk-severity";
import { OverviewSamplePreview } from "./_overview/sample-preview/overview-sample-preview";
import {
  FindingSeverityOverTimeSkeleton,
  FindingSeverityOverTimeSSR,
} from "./_overview/severity-over-time/finding-severity-over-time.ssr";
import { StatusChartSkeleton } from "./_overview/status-chart";
import { ThreatScoreSkeleton, ThreatScoreSSR } from "./_overview/threat-score";
import {
  ComplianceWatchlistSSR,
  ServiceWatchlistSSR,
  WatchlistCardSkeleton,
} from "./_overview/watchlist";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  // Resolved alongside the page data, so tenants with scans wait no longer.
  const [
    samplePreview,
    providersData,
    providerGroupsData,
    lighthouseBannerHref,
  ] = await Promise.all([
    getSamplePreviewState(),
    getAllProviders(),
    getAllProviderGroups(),
    getLighthouseOverviewBannerHref(isCloud(), getLighthouseV2Configurations),
  ]);

  // No completed scan yet: the demo account stands in for the tenant's data.
  if (samplePreview.active) {
    return (
      <ContentLayout title="Overview" icon={<SquareChartGantt />}>
        <AppSidebarModeSync mode={APP_SIDEBAR_MODE.BROWSE} />
        <SamplePreviewBanner
          state={samplePreview}
          page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        />
        <OverviewSamplePreview showIssues={isCloud()} />
      </ContentLayout>
    );
  }

  return (
    <ContentLayout title="Overview" icon={<SquareChartGantt />}>
      <AppSidebarModeSync mode={APP_SIDEBAR_MODE.BROWSE} />
      <OverviewProviderContext
        searchParams={resolvedSearchParams}
        providers={providersData?.data ?? []}
        groups={providerGroupsData?.data ?? []}
      />
      {/* Agents banner shows everywhere; Lighthouse is Cloud-only, so on a
          local server the agents banner is the only child and fills the row. */}
      <div className="mb-6 flex flex-col gap-6 lg:flex-row">
        {lighthouseBannerHref ? (
          <div className="min-w-0 lg:flex-1">
            <OverviewBanner
              variant={OVERVIEW_BANNER_VARIANT.LIGHTHOUSE}
              href={lighthouseBannerHref}
            />
          </div>
        ) : null}
        <div className="min-w-0 lg:flex-1">
          <OverviewBanner
            variant={OVERVIEW_BANNER_VARIANT.AGENTS}
            href={DOCS_URLS.AI_AGENTS}
          />
        </div>
      </div>

      <div className="xxl:grid-cols-4 mb-6 grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        <ProviderAccountSelectors providers={providersData?.data ?? []} />
        <ProviderGroupSelector groups={providerGroupsData?.data ?? []} />
      </div>

      <OverviewGrid
        threatScore={
          <Suspense fallback={<ThreatScoreSkeleton />}>
            <ThreatScoreSSR searchParams={resolvedSearchParams} />
          </Suspense>
        }
        exploitability={
          isCloud() ? (
            <FeatureFlagGate flag={FEATURE_FLAG.ISSUES}>
              <Suspense fallback={<ExploitabilityChartSkeleton />}>
                <ExploitabilityChartSSR searchParams={resolvedSearchParams} />
              </Suspense>
            </FeatureFlagGate>
          ) : undefined
        }
        checkFindings={
          <Suspense fallback={<StatusChartSkeleton />}>
            <CheckFindingsSSR searchParams={resolvedSearchParams} />
          </Suspense>
        }
        riskSeverity={
          <Suspense fallback={<RiskSeverityChartSkeleton />}>
            <RiskSeverityChartSSR searchParams={resolvedSearchParams} />
          </Suspense>
        }
        resourcesInventory={
          <Suspense fallback={<ResourcesInventorySkeleton />}>
            <ResourcesInventorySSR searchParams={resolvedSearchParams} />
          </Suspense>
        }
        complianceWatchlist={
          <Suspense fallback={<WatchlistCardSkeleton />}>
            <ComplianceWatchlistSSR searchParams={resolvedSearchParams} />
          </Suspense>
        }
        serviceWatchlist={
          <Suspense fallback={<WatchlistCardSkeleton />}>
            <ServiceWatchlistSSR searchParams={resolvedSearchParams} />
          </Suspense>
        }
        attackSurface={
          <Suspense fallback={<AttackSurfaceSkeleton />}>
            <AttackSurfaceSSR searchParams={resolvedSearchParams} />
          </Suspense>
        }
        topIssues={
          isCloud() ? (
            <FeatureFlagGate flag={FEATURE_FLAG.ISSUES}>
              <Suspense fallback={<TopIssuesSkeleton />}>
                <TopIssuesSSR searchParams={resolvedSearchParams} />
              </Suspense>
            </FeatureFlagGate>
          ) : undefined
        }
        severityOverTime={
          <Suspense fallback={<FindingSeverityOverTimeSkeleton />}>
            <FindingSeverityOverTimeSSR searchParams={resolvedSearchParams} />
          </Suspense>
        }
        graphsTabs={
          <Suspense fallback={<RiskPipelineViewSkeleton />}>
            <GraphsTabsWrapper searchParams={resolvedSearchParams} />
          </Suspense>
        }
      />
    </ContentLayout>
  );
}
