import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import {
  getFindings,
  getLatestFindings,
  getLatestMetadataInfo,
  getMetadataInfo,
} from "@/actions/findings";
import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { filterFindings } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import {
  ColumnFindings,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { ContentLayout } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import {
  createDict,
  createScanDetailsMapping,
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
} from "@/lib";
import {
  createProviderDetailsMapping,
  extractProviderUIDs,
} from "@/lib/provider-helpers";
import { ScanProps } from "@/types";
import { FindingProps, SearchParamsProps } from "@/types/components";

export default async function Findings({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const { searchParamsKey, encodedSort } = extractSortAndKey(searchParams);
  const { filters, query } = extractFiltersAndQuery(searchParams);

  // Check if the searchParams contain any date or scan filter
  const hasDateOrScan = hasDateOrScanFilter(searchParams);

  const [metadataInfoData, providersData, scansData] = await Promise.all([
    (hasDateOrScan ? getMetadataInfo : getLatestMetadataInfo)({
      query,
      sort: encodedSort,
      filters,
    }),
    getProviders({ pageSize: 50 }),
    getScans({ pageSize: 50 }),
  ]);

  // Extract unique regions and services from the new endpoint
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];
  const uniqueServices = metadataInfoData?.data?.attributes?.services || [];
  const uniqueResourceTypes =
    metadataInfoData?.data?.attributes?.resource_types || [];

  // Extract provider UIDs and details using helper functions
  const providerUIDs = providersData ? extractProviderUIDs(providersData) : [];
  const providerDetails = providersData
    ? createProviderDetailsMapping(providerUIDs, providersData)
    : [];

  // Update the Provider UID filter
  const updatedFilters = filterFindings.map((filter) => {
    if (filter.key === "provider_uid__in") {
      return {
        ...filter,
        values: providerUIDs,
        valueLabelMapping: providerDetails,
      };
    }
    return filter;
  });

  // Extract scan UUIDs with "completed" state and more than one resource
  const completedScans = scansData?.data?.filter(
    (scan: ScanProps) =>
      scan.attributes.state === "completed" &&
      scan.attributes.unique_resource_count > 1,
  );

  const completedScanIds =
    completedScans?.map((scan: ScanProps) => scan.id) || [];

  const scanDetails = createScanDetailsMapping(completedScans, providersData);

  return (
    <ContentLayout title="Findings" icon="carbon:data-view-alt">
      <FilterControls search date />
      <Spacer y={8} />
      <DataTableFilterCustom
        filters={[
          ...updatedFilters,
          {
            key: "region__in",
            labelCheckboxGroup: "Regions",
            values: uniqueRegions,
            index: 5,
          },
          {
            key: "service__in",
            labelCheckboxGroup: "Services",
            values: uniqueServices,
            index: 6,
          },
          {
            key: "resource_type__in",
            labelCheckboxGroup: "Resource Type",
            values: uniqueResourceTypes,
            index: 7,
          },
          {
            key: "scan__in",
            labelCheckboxGroup: "Scan ID",
            values: completedScanIds,
            valueLabelMapping: scanDetails,
            index: 9,
          },
        ]}
        defaultOpen={true}
      />
      <Spacer y={8} />

      <Suspense key={searchParamsKey} fallback={<SkeletonTableFindings />}>
        <SSRDataTable searchParams={searchParams} />
      </Suspense>
    </ContentLayout>
  );
}

const SSRDataTable = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
  const defaultSort = "severity,status,-inserted_at";

  const { encodedSort } = extractSortAndKey({
    ...searchParams,
    sort: searchParams.sort ?? defaultSort,
  });

  const { filters, query } = extractFiltersAndQuery(searchParams);
  // Check if the searchParams contain any date or scan filter
  const hasDateOrScan = hasDateOrScanFilter(searchParams);

  const fetchFindings = hasDateOrScan ? getFindings : getLatestFindings;

  const findingsData = await fetchFindings({
    query,
    page,
    sort: encodedSort,
    filters,
    pageSize,
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
        const provider = providerDict[scan?.relationships?.provider?.data?.id];

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
    <>
      {findingsData?.errors && (
        <div className="mb-4 flex rounded-lg border border-red-500 bg-red-100 p-2 text-small text-red-700">
          <p className="mr-2 font-semibold">Error:</p>
          <p>{findingsData.errors[0].detail}</p>
        </div>
      )}
      <DataTable
        columns={ColumnFindings}
        data={expandedResponse?.data || []}
        metadata={findingsData?.meta}
      />
    </>
  );
};
