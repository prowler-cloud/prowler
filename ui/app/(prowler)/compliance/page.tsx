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
import { ContentLayout } from "@/components/ui";
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
    return <NoScansAvailable />;
  }

  // Process scans with provider information from included data
  const expandedScansData: ExpandedScanData[] = scansData.data
    .filter((scan: ScanProps) => scan.relationships?.provider?.data?.id)
    .map((scan: ScanProps) => {
      const providerId = scan.relationships!.provider!.data!.id;

      // Find the provider data in the included array
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

  // Use scanId from URL, or select the first scan if not provided
  const scanIdParam = resolvedSearchParams.scanId;
  const scanIdFromUrl = Array.isArray(scanIdParam)
    ? scanIdParam[0]
    : scanIdParam;
  const selectedScanId: string | null =
    scanIdFromUrl || expandedScansData[0]?.id || null;

  // Find the selected scan
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

  // Fetch metadata if we have a selected scan
  const metadataInfoData = selectedScanId
    ? await getComplianceOverviewMetadataInfo({
        filters: {
          "filter[scan_id]": selectedScanId,
        },
      })
    : { data: { attributes: { regions: [] } } };

  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];

  // Fetch ThreatScore data from API if we have a selected scan
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
    <ContentLayout title="Compliance" icon="lucide:shield-check">
      {selectedScanId ? (
        <>
          {/* Row 1: Filters */}
          <div className="mb-6">
            <ComplianceFilters
              scans={expandedScansData}
              uniqueRegions={uniqueRegions}
              selectedScanId={selectedScanId}
            />
          </div>

          {/* Row 2: ThreatScore card — full width, horizontal */}
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

          {/* Row 3: Compliance grid with client-side search */}
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

  // Only fetch compliance data if we have a valid scanId
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

  // Check if the response contains no data
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

  // Handle errors returned by the API
  if (compliancesData?.errors?.length > 0) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertDescription>Provide a valid scan ID.</AlertDescription>
      </Alert>
    );
  }

  // Compute the set of latest CIS variants per provider once, so each card
  // can gate its PDF button without re-parsing on every render. The backend
  // only generates a CIS PDF for the latest version per provider, so any
  // other CIS card must not expose the PDF download button.
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
