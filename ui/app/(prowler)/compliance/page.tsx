export const dynamic = "force-dynamic";

import { Spacer } from "@nextui-org/react";
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
import { DataCompliance } from "@/components/compliance/data-compliance";
import { FilterControls } from "@/components/filters";
import { ContentLayout } from "@/components/ui";
import { DataTableFilterCustom } from "@/components/ui/table/data-table-filter-custom";
import { ComplianceOverviewData, ScanProps, SearchParamsProps } from "@/types";

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
  });

  if (!scansData?.data) {
    return <NoScansAvailable />;
  }

  // Expand scans with provider information
  const expandedScansData = await Promise.all(
    scansData.data.map(async (scan: ScanProps) => {
      const providerId = scan.relationships?.provider?.data?.id;

      if (!providerId) {
        return { ...scan, providerInfo: null };
      }

      const formData = new FormData();
      formData.append("id", providerId);

      const providerData = await getProvider(formData);

      return {
        ...scan,
        providerInfo: providerData?.data
          ? {
              provider: providerData.data.attributes.provider,
              uid: providerData.data.attributes.uid,
              alias: providerData.data.attributes.alias,
            }
          : null,
      };
    }),
  );

  const selectedScanId =
    searchParams.scanId || expandedScansData[0]?.id || null;
  const query = (filters["filter[search]"] as string) || "";

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
          <FilterControls search />
          <Spacer y={8} />
          <DataCompliance scans={expandedScansData} />
          <Spacer y={8} />
          <DataTableFilterCustom
            filters={[
              {
                key: "region__in",
                labelCheckboxGroup: "Regions",
                values: uniqueRegions,
              },
            ]}
            defaultOpen={true}
          />
          <Spacer y={12} />
          <Suspense key={searchParamsKey} fallback={<ComplianceSkeletonGrid />}>
            <SSRComplianceGrid searchParams={searchParams} />
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
}: {
  searchParams: SearchParamsProps;
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

  // Check if the response contains no data
  if (!compliancesData || compliancesData?.data?.length === 0) {
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
    // <AccordionExample />
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {compliancesData.data.map((compliance: ComplianceOverviewData) => {
        const { attributes } = compliance;
        const {
          framework,
          version,
          requirements_status: { passed, total },
          compliance_id,
        } = attributes;

        return (
          <ComplianceCard
            key={compliance.id}
            title={framework}
            version={version}
            passingRequirements={passed}
            totalRequirements={total}
            prevPassingRequirements={passed}
            prevTotalRequirements={total}
            scanId={scanId}
            complianceId={compliance_id}
            id={compliance.id}
          />
        );
      })}
    </div>
  );
};
