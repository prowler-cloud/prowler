import { Info } from "lucide-react";
import { Suspense } from "react";

import {
  getComplianceOverviewMetadataInfo,
  getCompliancesOverview,
} from "@/actions/compliances";
import { getThreatScore } from "@/actions/overview";
import { getScans } from "@/actions/scans";
import {
  ComplianceSkeletonGrid,
  NoScansAvailable,
  ThreatScoreBadge,
} from "@/components/compliance";
import { ComplianceFilters } from "@/components/compliance/compliance-header/compliance-filters";
import { ComplianceOverviewGrid } from "@/components/compliance/compliance-overview-grid";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { pickLatestCisPerProvider } from "@/lib/compliance/compliance-report-types";
import {
  ExpandedScanData,
  ScanEntity,
  ScanProps,
  SearchParamsProps,
} from "@/types";
import { ComplianceOverviewData } from "@/types/compliance";

export default async function Compliance({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

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

  return (
    <ContentLayout
      title="Compliance"
      icon="lucide:shield-check"
      onboardingAction={onboardingAction}
    >
      {selectedScanId ? (
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
      )}
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
      className="minimal-scrollbar relative z-0 w-full gap-4 overflow-auto shadow-sm"
    >
      <CardContent className="flex flex-col gap-4 p-4">{children}</CardContent>
    </Card>
  );
};
