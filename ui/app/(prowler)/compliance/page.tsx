import { Info } from "lucide-react";
import { Suspense } from "react";

import {
  getComplianceOverviewMetadataInfo,
  getCompliancesOverview,
  getCrossProviderComplianceOverview,
} from "@/actions/compliances";
import { getThreatScore } from "@/actions/overview";
import { getScans } from "@/actions/scans";
import {
  COMPLIANCE_PAGE_TAB,
  CompliancePageTabs,
  ComplianceSkeletonGrid,
  type CrossProviderFrameworkSummary,
  CrossProviderGrid,
  getCompliancePageTab,
  NoScansAvailable,
  ThreatScoreBadge,
} from "@/components/compliance";
import { ComplianceFilters } from "@/components/compliance/compliance-header/compliance-filters";
import { ComplianceOverviewGrid } from "@/components/compliance/compliance-overview-grid";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/ui";
import { pickLatestCisPerProvider } from "@/lib/compliance/compliance-report-types";
import { UNIVERSAL_FRAMEWORKS } from "@/lib/compliance/universal-frameworks";
import { isCloud } from "@/lib/shared/env";
import {
  ExpandedScanData,
  ScanEntity,
  ScanProps,
  SearchParamsProps,
} from "@/types";
import {
  ComplianceOverviewData,
  CrossProviderComplianceOverviewData,
} from "@/types/compliance";

export default async function Compliance({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

  // Cross-Provider is a Prowler Cloud-only feature; the OSS API has no
  // cross-provider-compliance-overviews endpoint. In OSS the tab is shown
  // disabled with an upsell badge and the per-scan tab is forced active.
  const crossProviderEnabled = isCloud();
  const activeTab = crossProviderEnabled
    ? getCompliancePageTab(resolvedSearchParams.tab)
    : COMPLIANCE_PAGE_TAB.PER_SCAN;

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
        <NoScansAvailable />
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
        />
      </Suspense>
    </>
  ) : (
    <NoScansAvailable />
  );

  // Only build (and thus fetch) the cross-provider grid in Cloud. In OSS the
  // tab is disabled, so there is no content to render and no endpoint to hit.
  const crossProviderContent = crossProviderEnabled ? (
    <Suspense
      key={`cross-provider-${searchParamsKey}`}
      fallback={
        <ComplianceOverviewPanel>
          <ComplianceSkeletonGrid />
        </ComplianceOverviewPanel>
      }
    >
      <SSRCrossProviderGrid searchParams={resolvedSearchParams} />
    </Suspense>
  ) : null;

  return (
    <ContentLayout
      title="Compliance"
      icon="lucide:shield-check"
      onboardingAction={onboardingAction}
    >
      <CompliancePageTabs
        activeTab={activeTab}
        perScanContent={perScanContent}
        crossProviderContent={crossProviderContent}
        crossProviderEnabled={crossProviderEnabled}
      />
    </ContentLayout>
  );
}

const SSRComplianceGrid = async ({
  searchParams,
  scanId,
  selectedScan,
}: {
  searchParams: SearchParamsProps;
  scanId: string | null;
  selectedScan?: ScanEntity;
}) => {
  const regionFilter = searchParams["filter[region__in]"]?.toString() || "";

  const compliancesData =
    scanId && scanId.trim() !== ""
      ? await getCompliancesOverview({
          scanId,
          region: regionFilter,
        })
      : { data: [], errors: [] };

  const type = compliancesData?.data?.type;
  const frameworks = compliancesData?.data
    ?.filter((compliance: ComplianceOverviewData) => {
      return compliance.attributes.framework !== "ProwlerThreatScore";
    })
    .sort((a: ComplianceOverviewData, b: ComplianceOverviewData) =>
      a.attributes.framework.localeCompare(b.attributes.framework),
    );

  if (
    !compliancesData ||
    !compliancesData.data ||
    compliancesData.data.length === 0 ||
    type === "tasks"
  ) {
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

  if (compliancesData?.errors?.length > 0) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertDescription>Provide a valid scan ID.</AlertDescription>
      </Alert>
    );
  }

  // Backend only generates CIS PDFs for the latest version per provider.
  const latestCisIds = pickLatestCisPerProvider(
    compliancesData.data.map(
      (compliance: ComplianceOverviewData) => compliance.id,
    ),
  );

  return (
    <ComplianceOverviewPanel>
      <ComplianceOverviewGrid
        frameworks={frameworks}
        scanId={scanId ?? ""}
        selectedScan={selectedScan}
        latestCisIds={latestCisIds}
      />
    </ComplianceOverviewPanel>
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
      className="minimal-scrollbar shadow-small relative z-0 w-full gap-4 overflow-auto"
    >
      <CardContent className="flex flex-col gap-4 p-4">{children}</CardContent>
    </Card>
  );
};

/**
 * Server-side island for the Cross-Provider tab.
 *
 * Iterates the hardcoded ``UNIVERSAL_FRAMEWORKS`` catalogue and fetches the
 * cross-provider roll-up for each one in parallel. The summaries hydrate the
 * grid of cards so the user sees per-framework totals without an extra
 * client round-trip. Today there is a single entry (CSA CCM 4.0); when the
 * SDK ships more universal JSONs, only the catalogue file changes.
 */
const SSRCrossProviderGrid = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const providerTypes =
    searchParams["filter[provider_type__in]"]?.toString() || undefined;
  const regions = searchParams["filter[region__in]"]?.toString() || undefined;

  const responses = await Promise.all(
    UNIVERSAL_FRAMEWORKS.map((entry) =>
      getCrossProviderComplianceOverview({
        complianceId: entry.id,
        providerTypes,
        regions,
      }).then((response) => ({ entry, response })),
    ),
  );

  const summaries: CrossProviderFrameworkSummary[] = [];
  for (const { entry, response } of responses) {
    if (!response || "redirectTo" in response) continue;
    const data = (response as { data?: CrossProviderComplianceOverviewData })
      .data;
    if (!data) {
      // Catalogue entry exists but the API returned nothing usable —
      // surface a zero-card so the user still sees the framework with all
      // its compatible providers chips dimmed (no scan yet).
      summaries.push({
        id: entry.id,
        title: entry.title,
        version: entry.version,
        description: entry.description,
        requirementsPassed: 0,
        totalRequirements: 0,
        contributingProviders: [],
        compatibleProviders: entry.providers,
      });
      continue;
    }
    const attrs = data.attributes;
    // ``compatible_providers`` from the API is authoritative; fall back to
    // the catalogue entry only if the response omitted it.
    const compatible =
      attrs.compatible_providers && attrs.compatible_providers.length > 0
        ? attrs.compatible_providers
        : entry.providers;
    summaries.push({
      id: entry.id,
      title: attrs.framework || entry.title,
      version: attrs.version || entry.version,
      description: attrs.description || entry.description,
      requirementsPassed: attrs.requirements_passed,
      totalRequirements: attrs.total_requirements,
      contributingProviders: attrs.providers,
      compatibleProviders: compatible,
    });
  }

  if (summaries.length === 0) {
    return (
      <ComplianceOverviewPanel>
        <Alert variant="info">
          <Info className="size-4" />
          <AlertDescription>
            No universal compliance frameworks are available yet.
          </AlertDescription>
        </Alert>
      </ComplianceOverviewPanel>
    );
  }

  return (
    <ComplianceOverviewPanel>
      <CrossProviderGrid frameworks={summaries} />
    </ComplianceOverviewPanel>
  );
};
