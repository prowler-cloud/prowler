import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import { getFindings } from "@/actions/findings";
import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { filterFindings } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import {
  ColumnFindings,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { Header } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { createDict } from "@/lib";
import { FindingProps, SearchParamsProps } from "@/types/components";

export default async function Findings({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  // Get findings data
  const findingsData = await getFindings({});
  const providersData = await getProviders({});
  const scansData = await getScans({});

  // Extract provider UIDs
  const providerUIDs = providersData?.data
    ?.map((provider: any) => provider.attributes.uid)
    .filter(Boolean);

  // Extract scan UUIDs with "completed" state and more than one resource
  const completedScans = scansData?.data
    ?.filter(
      (scan: any) =>
        scan.attributes.state === "completed" &&
        scan.attributes.unique_resource_count > 1 &&
        scan.attributes.name, // Ensure it has a name
    )
    .map((scan: any) => ({
      id: scan.id,
      name: scan.attributes.name,
    }));

  const completedScanIds = completedScans?.map((scan: any) => scan.id) || [];

  // Create resource dictionary
  const resourceDict = createDict("resources", findingsData);

  // Get unique regions and services
  const allRegionsAndServices =
    findingsData?.data
      ?.flatMap((finding: FindingProps) => {
        const resource =
          resourceDict[finding.relationships?.resources?.data?.[0]?.id];
        return {
          region: resource?.attributes?.region,
          service: resource?.attributes?.service,
        };
      })
      .filter(Boolean) || [];

  const uniqueRegions = Array.from(
    new Set<string>(
      allRegionsAndServices
        .map((item: { region: string }) => item.region)
        .filter(Boolean) || [],
    ),
  );
  const uniqueServices = Array.from(
    new Set<string>(
      allRegionsAndServices
        .map((item: { service: string }) => item.service)
        .filter(Boolean) || [],
    ),
  );

  return (
    <>
      <Header title="Findings" icon="ph:list-checks-duotone" />
      <Spacer />
      <Spacer y={4} />
      <FilterControls search date />
      <Spacer y={8} />
      <DataTableFilterCustom
        filters={[
          ...filterFindings,
          {
            key: "region__in",
            labelCheckboxGroup: "Regions",
            values: uniqueRegions,
          },
          {
            key: "service__in",
            labelCheckboxGroup: "Services",
            values: uniqueServices,
          },
          {
            key: "provider_uid__in",
            labelCheckboxGroup: "Account",
            values: providerUIDs,
          },
          {
            key: "scan__in",
            labelCheckboxGroup: "Scans",
            values: completedScanIds, // Use UUIDs in the filter
          },
        ]}
        defaultOpen={true}
      />
      <Spacer y={8} />
      <Suspense key={searchParamsKey} fallback={<SkeletonTableFindings />}>
        <SSRDataTable searchParams={searchParams} />
      </Suspense>
    </>
  );
}

const SSRDataTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const sort = searchParams.sort?.toString();

  // Extract all filter parameters
  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  );

  // Extract query from filters
  const query = (filters["filter[search]"] as string) || "";

  const findingsData = await getFindings({ query, page, sort, filters });

  // Create dictionaries for resources, scans, and providers
  const resourceDict = createDict("resources", findingsData);
  const scanDict = createDict("scans", findingsData);
  const providerDict = createDict("providers", findingsData);

  // Expand each finding with its corresponding resource, scan, and provider
  const expandedFindings = findingsData?.data
    ? findingsData.data.map((finding: FindingProps) => {
        const scan = scanDict[finding.relationships?.scan?.data?.id];
        const resource =
          resourceDict[finding.relationships?.resources?.data?.[0]?.id];
        const provider =
          providerDict[resource?.relationships?.provider?.data?.id];

        return {
          ...finding,
          relationships: { scan, resource, provider },
        };
      })
    : [];

  // Create the new object while maintaining the original structure
  const expandedResponse = {
    ...findingsData,
    data: expandedFindings,
  };

  return (
    <DataTable
      columns={ColumnFindings}
      data={expandedResponse?.data || []}
      metadata={findingsData?.meta}
    />
  );
};
