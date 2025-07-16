import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import {
  getLatestMetadataInfo,
  getLatestResources,
  getMetadataInfo,
  getResources,
} from "@/actions/resources";
import { FilterControls } from "@/components/filters";
import { SkeletonTableResources } from "@/components/resources/skeleton/skeleton-table-resources";
import { ColumnResources } from "@/components/resources/table/column-resources";
import { ContentLayout } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import {
  createDict,
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
  replaceFieldKey,
} from "@/lib";
import { ResourceProps, SearchParamsProps } from "@/types";

export default async function Resources({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const { searchParamsKey, encodedSort } = extractSortAndKey(searchParams);
  const { filters, query } = extractFiltersAndQuery(searchParams);
  const outputFilters = replaceFieldKey(filters, "inserted_at", "updated_at");

  // Check if the searchParams contain any date or scan filter
  const hasDateOrScan = hasDateOrScanFilter(searchParams);

  const metadataInfoData = await (
    hasDateOrScan ? getMetadataInfo : getLatestMetadataInfo
  )({
    query,
    filters: outputFilters,
    sort: encodedSort,
  });

  // Extract unique regions, services, types, and names from the metadata endpoint
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];
  const uniqueServices = metadataInfoData?.data?.attributes?.services || [];
  const uniqueResourceTypes = metadataInfoData?.data?.attributes?.types || [];

  return (
    <ContentLayout title="Resources" icon="carbon:data-view">
      <FilterControls search date />
      <DataTableFilterCustom
        filters={[
          {
            key: "region",
            labelCheckboxGroup: "Region",
            values: uniqueRegions,
          },
          {
            key: "type",
            labelCheckboxGroup: "Type",
            values: uniqueResourceTypes,
          },
          {
            key: "service",
            labelCheckboxGroup: "Service",
            values: uniqueServices,
          },
        ]}
        defaultOpen={true}
      />
      <Spacer y={8} />
      <Suspense key={searchParamsKey} fallback={<SkeletonTableResources />}>
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
  const { encodedSort } = extractSortAndKey({
    ...searchParams,
    ...(searchParams.sort && { sort: searchParams.sort }),
  });

  const { filters, query } = extractFiltersAndQuery(searchParams);
  // Check if the searchParams contain any date or scan filter
  const hasDateOrScan = hasDateOrScanFilter(searchParams);

  const outputFilters = replaceFieldKey(filters, "inserted_at", "updated_at");

  const fetchResources = hasDateOrScan ? getResources : getLatestResources;

  const resourcesData = await fetchResources({
    query,
    page,
    sort: encodedSort,
    filters: outputFilters,
    pageSize,
    include: "provider",
    fields: [
      "name",
      "failed_findings_count",
      "region",
      "service",
      "type",
      "provider",
      "inserted_at",
      "updated_at",
      "uid",
    ],
  });

  // Create dictionary for providers (removed findings dict since we're not including findings anymore)
  const providerDict = createDict("providers", resourcesData);

  // Expand each resource with its corresponding provider (removed findings expansion)
  const expandedResources = resourcesData?.data
    ? resourcesData.data.map((resource: ResourceProps) => {
        const provider = {
          data: providerDict[resource.relationships.provider.data.id],
        };

        return {
          ...resource,
          relationships: {
            ...resource.relationships,
            provider,
          },
        };
      })
    : [];

  return (
    <>
      {resourcesData?.errors && (
        <div className="mb-4 flex rounded-lg border border-red-500 bg-red-100 p-2 text-small text-red-700">
          <p className="mr-2 font-semibold">Error:</p>
          <p>{resourcesData.errors[0].detail}</p>
        </div>
      )}
      <DataTable
        columns={ColumnResources}
        data={expandedResources || []}
        metadata={resourcesData?.meta}
      />
    </>
  );
};
