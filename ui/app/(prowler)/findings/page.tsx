import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import { getFindings, getServicesRegions } from "@/actions/findings";
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
import {
  FindingProps,
  ProviderProps,
  ScanProps,
  SearchParamsProps,
} from "@/types/components";

export default async function Findings({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});
  const defaultSort = "severity,status";
  const sort = searchParams.sort?.toString() || defaultSort;

  // Make sure the sort is correctly encoded
  const encodedSort = sort.replace(/^\+/, "");

  // Extract all filter parameters and combine with default filters
  const defaultFilters = {
    "filter[status__in]": "FAIL, PASS",
    "filter[delta__in]": "new",
  };

  const filters: Record<string, string> = {
    ...defaultFilters,
    ...Object.fromEntries(
      Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
    ),
  };

  const query = filters["filter[search]"] || "";

  const servicesRegionsData = await getServicesRegions({
    query,
    sort: encodedSort,
    filters,
  });

  // Extract unique regions and services from the new endpoint
  const uniqueRegions = servicesRegionsData?.data?.attributes?.regions || [];
  const uniqueServices = servicesRegionsData?.data?.attributes?.services || [];
  // Get findings data
  const providersData = await getProviders({});
  const scansData = await getScans({});

  // Extract provider UIDs
  const providerUIDs = Array.from(
    new Set(
      providersData?.data
        ?.map((provider: ProviderProps) => provider.attributes.uid)
        .filter(Boolean),
    ),
  );

  // Extract scan UUIDs with "completed" state and more than one resource
  const completedScans = scansData?.data
    ?.filter(
      (scan: any) =>
        scan.attributes.state === "completed" &&
        scan.attributes.unique_resource_count > 1,
    )
    .map((scan: ScanProps) => ({
      id: scan.id,
      name: scan.attributes.name,
    }));

  const completedScanIds =
    completedScans?.map((scan: ScanProps) => scan.id) || [];

  return (
    <>
      <Header title="Findings" icon="carbon:data-view-alt" />
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
            labelCheckboxGroup: "Provider UID",
            values: providerUIDs,
          },
          {
            key: "scan__in",
            labelCheckboxGroup: "Scan ID",
            values: completedScanIds,
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
  const defaultSort = "severity,status";
  const sort = searchParams.sort?.toString() || defaultSort;

  // Make sure the sort is correctly encoded
  const encodedSort = sort.replace(/^\+/, "");

  // Extract all filter parameters and combine with default filters
  const defaultFilters = {
    "filter[status__in]": "FAIL, PASS",
  };

  const filters: Record<string, string> = {
    ...defaultFilters,
    ...Object.fromEntries(
      Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
    ),
  };

  const query = filters["filter[search]"] || "";

  const findingsData = await getFindings({
    query,
    page,
    sort: encodedSort,
    filters,
    pageSize: 10,
  });

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
