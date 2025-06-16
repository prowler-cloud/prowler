export const dynamic = "force-dynamic";
import { Suspense } from "react";

import { getCompliancesOverview } from "@/actions/compliances";
import { getComplianceOverviewMetadataInfo } from "@/actions/compliances";
import { getProvider } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import {
  ComplianceCard,
  ComplianceSkeletonGrid,
  NoScansAvailable,
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
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  );

  const scansData = await getScans({
    filters: {
      "filter[state]": "completed",
    },
    pageSize: 50,
  });

  if (!scansData?.data) {
    return <NoScansAvailable />;
  }

  // Expand scans with provider information - only include scans with valid provider
  const expandedScansData: ExpandedScanData[] = await Promise.all(
    scansData.data
      .filter((scan: ScanProps) => scan.relationships?.provider?.data?.id)
      .map(async (scan: ScanProps) => {
        const providerId = scan.relationships!.provider!.data!.id;

        const formData = new FormData();
        formData.append("id", providerId);

        const providerData = await getProvider(formData);

        return {
          ...scan,
          providerInfo: {
            provider: providerData.data.attributes.provider,
            uid: providerData.data.attributes.uid,
            alias: providerData.data.attributes.alias,
          },
        };
      }),
  );

  const selectedScanId =
    searchParams.scanId || expandedScansData[0]?.id || null;
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

  const metadataInfoData = await getComplianceOverviewMetadataInfo({
    query,
    filters: {
      "filter[scan_id]": selectedScanId,
    },
  });

  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];

  return (
    <ContentLayout title="Compliance" icon="fluent-mdl2:compliance-audit">
      {selectedScanId ? (
        <>
          <ComplianceHeader
            scans={expandedScansData}
            uniqueRegions={uniqueRegions}
          />
          <Suspense key={searchParamsKey} fallback={<ComplianceSkeletonGrid />}>
            <SSRComplianceGrid
              searchParams={searchParams}
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

  const compliancesData = await getCompliancesOverview({
    scanId,
    region: regionFilter,
    query,
  });

  const type = compliancesData?.data?.[0]?.type;

  // Check if the response contains no data
  if (
    !compliancesData ||
    !compliancesData.data ||
    compliancesData.data.length === 0 ||
    type === "tasks"
  ) {
    return (
      <div className="flex h-full items-center">
        <div className="text-sm text-default-500">
          No compliance data available for the selected scan.
        </div>
      </div>
    );
  }

  // Handle errors returned by the API
  if (compliancesData?.errors?.length > 0) {
    return (
      <div className="flex h-full items-center">
        <div className="text-sm text-default-500">Provide a valid scan ID.</div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {compliancesData.data.map((compliance: ComplianceOverviewData) => {
        const { attributes, id } = compliance;
        const { framework, version, requirements_passed, total_requirements } =
          attributes;

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
