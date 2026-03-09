import { Suspense } from "react";

import {
  getComplianceOverviewMetadataInfo,
  getCompliancesOverview,
} from "@/actions/compliances";
import { getThreatScore } from "@/actions/overview";
import { getScans } from "@/actions/scans";
import {
  ComplianceCard,
  ComplianceSkeletonGrid,
  NoScansAvailable,
  ThreatScoreBadge,
} from "@/components/compliance";
import { ComplianceHeader } from "@/components/compliance/compliance-header/compliance-header";
import { ContentLayout } from "@/components/ui";
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

  const filters = Object.fromEntries(
    Object.entries(resolvedSearchParams).filter(([key]) =>
      key.startsWith("filter["),
    ),
  );

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
  const selectedScanId =
    resolvedSearchParams.scanId || expandedScansData[0]?.id || null;
  const query = (filters["filter[search]"] as string) || "";

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
        query,
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
          <div className="mb-6 flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0 flex-1">
              <ComplianceHeader
                scans={expandedScansData}
                uniqueRegions={uniqueRegions}
              />
            </div>
            {threatScoreData &&
              typeof selectedScanId === "string" &&
              selectedScan && (
                <div className="w-full lg:w-[360px] lg:flex-shrink-0">
                  <ThreatScoreBadge
                    score={threatScoreData.score}
                    scanId={selectedScanId}
                    provider={selectedScan.providerInfo.provider}
                    selectedScan={selectedScanData}
                    sectionScores={threatScoreData.sectionScores}
                  />
                </div>
              )}
          </div>
          <Suspense key={searchParamsKey} fallback={<ComplianceSkeletonGrid />}>
            <SSRComplianceGrid
              searchParams={resolvedSearchParams}
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
  selectedScan,
}: {
  searchParams: SearchParamsProps;
  selectedScan?: ScanEntity;
}) => {
  const scanId = searchParams.scanId?.toString() || "";
  const regionFilter = searchParams["filter[region__in]"]?.toString() || "";

  // Extract all filter parameters
  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  );

  // Extract query from filters
  const query = (filters["filter[search]"] as string) || "";

  // Only fetch compliance data if we have a valid scanId
  const compliancesData =
    scanId && scanId.trim() !== ""
      ? await getCompliancesOverview({
          scanId,
          region: regionFilter,
          query,
        })
      : { data: [], errors: [] };

  const type = compliancesData?.data?.type;

  // Check if the response contains no data
  if (
    !compliancesData ||
    !compliancesData.data ||
    compliancesData.data.length === 0 ||
    type === "tasks"
  ) {
    return (
      <div className="flex h-full items-center">
        <div className="text-default-500 text-sm">
          No compliance data available for the selected scan.
        </div>
      </div>
    );
  }

  // Handle errors returned by the API
  if (compliancesData?.errors?.length > 0) {
    return (
      <div className="flex h-full items-center">
        <div className="text-default-500 text-sm">Provide a valid scan ID.</div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {compliancesData.data
        .filter((compliance: ComplianceOverviewData) => {
          // Filter out ProwlerThreatScore from the grid
          return compliance.attributes.framework !== "ProwlerThreatScore";
        })
        .sort((a: ComplianceOverviewData, b: ComplianceOverviewData) =>
          a.attributes.framework.localeCompare(b.attributes.framework),
        )
        .map((compliance: ComplianceOverviewData) => {
          const { attributes, id } = compliance;
          const {
            framework,
            version,
            requirements_passed,
            total_requirements,
          } = attributes;

          return (
            <ComplianceCard
              key={id}
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
            />
          );
        })}
    </div>
  );
};
