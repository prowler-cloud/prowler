import { Info } from "lucide-react";
import { Suspense } from "react";

import {
  COMPLIANCE_OVERVIEW_RESOURCE_TYPE,
  getComplianceOverviewMetadataInfo,
  getCompliancesOverview,
} from "@/actions/compliances";
import { getThreatScore } from "@/actions/overview";
import { getScans, getScansByState } from "@/actions/scans";
import {
  ComplianceSkeletonGrid,
  NoScansAvailable,
  ThreatScoreBadge,
} from "@/components/compliance";
import { ComplianceFilters } from "@/components/compliance/compliance-header/compliance-filters";
import { ComplianceOverviewGrid } from "@/components/compliance/compliance-overview-grid";
import { WatchlistControls } from "@/components/compliance/watchlist/watchlist-controls";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { pickLatestCisPerProvider } from "@/lib/compliance/compliance-report-types";
import { isCloud } from "@/lib/shared/env";
import {
  ExpandedScanData,
  ScanEntity,
  ScanProps,
  SearchParamsProps,
} from "@/types";
import { COMPLIANCE_TAB, ComplianceOverviewData } from "@/types/compliance";

import { CompliancePageTabs } from "./_components/compliance-page-tabs";
import { getComplianceTab } from "./_components/compliance-page-tabs.shared";
import { CrossAccountOverviewSection } from "./_components/cross-account-overview-section";
import { CrossProviderOverview } from "./_components/cross-provider-overview";
import {
  CrossAccountOverviewSkeleton,
  CrossProviderOverviewSkeleton,
} from "./_components/multiple-scans-skeleton";
import type { ComplianceWatchlistContext } from "./_lib/watchlist-context";
import { loadComplianceWatchlistContext } from "./_lib/watchlist-context";

export default async function Compliance({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

  // Cross-Provider is Prowler Cloud-only (the OSS API has no
  // cross-provider-compliance-overviews endpoint). It is the landing tab in
  // Cloud; in OSS its trigger only carries the upsell badge, so Per Scan
  // stays active regardless of `?tab=`.
  const crossProviderEnabled = isCloud();
  const activeTab = crossProviderEnabled
    ? getComplianceTab(resolvedSearchParams.tab, resolvedSearchParams.scanId)
    : COMPLIANCE_TAB.PER_SCAN;

  const watchlistPromise = loadComplianceWatchlistContext();
  const watchlistControls = (
    <Suspense fallback={null}>
      <ComplianceWatchlistControls watchlistPromise={watchlistPromise} />
    </Suspense>
  );

  // Only the active tab's payload is built: switching tabs is a real
  // navigation, so pre-building the inactive tab buys nothing.
  if (activeTab === COMPLIANCE_TAB.CROSS_PROVIDER) {
    // The tour's anchors (search, framework cards) only exist on Single Scan,
    // so replaying it from here navigates there — and with no scan to render
    // those anchors never mount. Fall back to the scan flow instead, matching
    // the Per Scan branch below. Fail-open: a failed fetch assumes scans exist.
    const scansByState = await getScansByState();
    const hasCompletedScan = Array.isArray(scansByState?.data)
      ? scansByState.data.length > 0
      : true;

    return (
      <ContentLayout
        title="Compliance"
        icon="lucide:shield-check"
        onboardingAction={
          hasCompletedScan
            ? { flowId: "view-compliance" }
            : {
                flowId: "view-compliance",
                fallbackFlowId: "view-first-scan",
                useFallback: true,
              }
        }
      >
        <CompliancePageTabs
          activeTab={activeTab}
          crossProviderEnabled={crossProviderEnabled}
          watchlistControls={watchlistControls}
          perScanContent={null}
          crossProviderContent={
            // gap-6 = the app-wide 24px below a filter row (Findings and the
            // Single Scan tab both use mb-6), so filters→"Across provider
            // types" and cards→"Across providers" read as one rhythm.
            <div className="flex flex-col gap-6">
              <Suspense
                key={`cross-provider-${searchParamsKey}`}
                fallback={<CrossProviderOverviewSkeleton />}
              >
                <CrossProviderOverview searchParams={resolvedSearchParams} />
              </Suspense>
              {/* Regular per-provider frameworks viewable across accounts.
                  Its fallback mirrors the provider groups while this island
                  loads independently from the universal frameworks above. */}
              <Suspense
                key={`cross-account-${searchParamsKey}`}
                fallback={<CrossAccountOverviewSkeleton />}
              >
                <CrossAccountOverviewSection
                  searchParams={resolvedSearchParams}
                />
              </Suspense>
            </div>
          }
        />
      </ContentLayout>
    );
  }

  const scansData = await getScans({
    filters: {
      "filter[state]": "completed",
    },
    pageSize: 50,
    fields: {
      scans: "name,completed_at,provider",
    },
    include: "provider",
  });

  if (!scansData?.data) {
    return (
      <ContentLayout
        title="Compliance"
        icon="lucide:shield-check"
        onboardingAction={{
          flowId: "view-compliance",
          fallbackFlowId: "view-first-scan",
          useFallback: true,
        }}
      >
        <CompliancePageTabs
          activeTab={activeTab}
          crossProviderEnabled={crossProviderEnabled}
          watchlistControls={watchlistControls}
          perScanContent={<NoScansAvailable />}
          crossProviderContent={null}
        />
      </ContentLayout>
    );
  }

  const expandedScansData: ExpandedScanData[] = scansData.data
    .filter((scan: ScanProps) => scan.relationships?.provider?.data?.id)
    .map((scan: ScanProps) => {
      const providerId = scan.relationships!.provider!.data!.id;

      const providerData = scansData.included?.find(
        (item: { type: string; id: string }) =>
          item.type === "providers" && item.id === providerId,
      );

      if (!providerData) {
        return null;
      }

      return {
        ...scan,
        providerInfo: {
          provider: providerData.attributes.provider,
          uid: providerData.attributes.uid,
          alias: providerData.attributes.alias,
        },
      };
    })
    .filter(Boolean) as ExpandedScanData[];

  const scanIdParam = resolvedSearchParams.scanId;
  const scanIdFromUrl = Array.isArray(scanIdParam)
    ? scanIdParam[0]
    : scanIdParam;
  const selectedScanId: string | null =
    scanIdFromUrl || expandedScansData[0]?.id || null;
  const onboardingAction = selectedScanId
    ? { flowId: "view-compliance" }
    : {
        flowId: "view-compliance",
        fallbackFlowId: "view-first-scan",
        useFallback: true,
      };

  const selectedScan = expandedScansData.find(
    (scan) => scan.id === selectedScanId,
  );

  const selectedScanData: ScanEntity | undefined = selectedScan?.providerInfo
    ? {
        id: selectedScan.id,
        providerInfo: selectedScan.providerInfo,
        attributes: {
          name: selectedScan.attributes.name,
          completed_at: selectedScan.attributes.completed_at,
        },
      }
    : undefined;

  const metadataInfoData = selectedScanId
    ? await getComplianceOverviewMetadataInfo({
        filters: {
          "filter[scan_id]": selectedScanId,
        },
      })
    : { data: { attributes: { regions: [] } } };

  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];

  let threatScoreData = null;
  if (selectedScanId && typeof selectedScanId === "string") {
    const threatScoreResponse = await getThreatScore({
      filters: { "filter[scan_id]": selectedScanId },
    });

    if (threatScoreResponse?.data && threatScoreResponse.data.length > 0) {
      const snapshot = threatScoreResponse.data[0];
      threatScoreData = {
        score: parseFloat(snapshot.attributes.overall_score),
        sectionScores: snapshot.attributes.section_scores,
      };
    }
  }

  const perScanContent = selectedScanId ? (
    <>
      <div className="mb-6">
        <ComplianceFilters
          scans={expandedScansData}
          uniqueRegions={uniqueRegions}
          selectedScanId={selectedScanId}
        />
      </div>

      {threatScoreData &&
        typeof selectedScanId === "string" &&
        selectedScan && (
          <div className="mb-6">
            <ThreatScoreBadge
              score={threatScoreData.score}
              scanId={selectedScanId}
              provider={selectedScan.providerInfo.provider}
              selectedScan={selectedScanData}
              sectionScores={threatScoreData.sectionScores}
            />
          </div>
        )}

      <Suspense
        key={searchParamsKey}
        fallback={
          <ComplianceOverviewPanel>
            <ComplianceSkeletonGrid />
          </ComplianceOverviewPanel>
        }
      >
        <SSRComplianceGrid
          searchParams={resolvedSearchParams}
          scanId={selectedScanId}
          selectedScan={selectedScanData}
          watchlistPromise={watchlistPromise}
        />
      </Suspense>
    </>
  ) : (
    <NoScansAvailable />
  );

  return (
    <ContentLayout
      title="Compliance"
      icon="lucide:shield-check"
      onboardingAction={onboardingAction}
    >
      <CompliancePageTabs
        activeTab={activeTab}
        crossProviderEnabled={crossProviderEnabled}
        watchlistControls={watchlistControls}
        perScanContent={perScanContent}
        crossProviderContent={null}
      />
    </ContentLayout>
  );
}

const SSRComplianceGrid = async ({
  searchParams,
  scanId,
  selectedScan,
  watchlistPromise,
}: {
  searchParams: SearchParamsProps;
  scanId: string | null;
  selectedScan?: ScanEntity;
  watchlistPromise: Promise<ComplianceWatchlistContext>;
}) => {
  const regionFilter = searchParams["filter[region__in]"]?.toString() || "";

  const compliancesData =
    scanId && scanId.trim() !== ""
      ? await getCompliancesOverview({
          scanId,
          region: regionFilter,
        })
      : { data: [], errors: [] };

  const complianceData = compliancesData?.data;

  if (
    compliancesData &&
    "errors" in compliancesData &&
    compliancesData.errors &&
    compliancesData.errors.length > 0
  ) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertDescription>Provide a valid scan ID.</AlertDescription>
      </Alert>
    );
  }

  if (
    !Array.isArray(complianceData) &&
    complianceData?.type === COMPLIANCE_OVERVIEW_RESOURCE_TYPE.TASK
  ) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertDescription>
          Compliance data is still being generated. Please try again shortly.
        </AlertDescription>
      </Alert>
    );
  }

  if (!Array.isArray(complianceData) || complianceData.length === 0) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertDescription>
          This scan has no compliance data available yet, please select a
          different one.
        </AlertDescription>
      </Alert>
    );
  }

  const frameworks = complianceData
    .filter((compliance: ComplianceOverviewData) => {
      return compliance.attributes.framework !== "ProwlerThreatScore";
    })
    .sort((a: ComplianceOverviewData, b: ComplianceOverviewData) =>
      a.attributes.framework.localeCompare(b.attributes.framework),
    );

  // Backend only generates CIS PDFs for the latest version per provider.
  const latestCisIds = pickLatestCisPerProvider(
    complianceData.map((compliance: ComplianceOverviewData) => compliance.id),
  );

  // The watchlist is keyed by `(compliance_id, provider_type)`, and on this
  // surface the provider type is fixed by the selected scan.
  const providerType = selectedScan?.providerInfo.provider;
  const watchlist = await watchlistPromise;

  return (
    <ComplianceOverviewPanel>
      <ComplianceOverviewGrid
        frameworks={frameworks}
        scanId={scanId ?? ""}
        selectedScan={selectedScan}
        latestCisIds={latestCisIds}
        catalogEntries={watchlist.entries}
        providerType={providerType}
        canManageWatchlist={watchlist.canManage}
      />
    </ComplianceOverviewPanel>
  );
};

const ComplianceWatchlistControls = async ({
  watchlistPromise,
}: {
  watchlistPromise: Promise<ComplianceWatchlistContext>;
}) => {
  const watchlist = await watchlistPromise;

  return (
    <WatchlistControls
      entries={watchlist.entries}
      canManageWatchlist={watchlist.canManage}
    />
  );
};

const ComplianceOverviewPanel = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  return (
    <Card
      variant="base"
      padding="none"
      className="minimal-scrollbar relative z-0 w-full gap-4 overflow-auto shadow-sm"
    >
      <CardContent className="flex flex-col gap-4 p-4">{children}</CardContent>
    </Card>
  );
};
