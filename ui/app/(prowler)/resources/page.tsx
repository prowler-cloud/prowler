import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import {
  getLatestMetadataInfo,
  getLatestResources,
  getMetadataInfo,
  getResourceById,
  getResources,
} from "@/actions/resources";
import { ResourceDetailsSheet } from "@/components/resources/resource-details-sheet";
import { ResourcesFilters } from "@/components/resources/resources-filters";
import { SkeletonTableResources } from "@/components/resources/skeleton/skeleton-table-resources";
import { ResourcesTableWithSelection } from "@/components/resources/table";
import { ContentLayout } from "@/components/ui";
import { FilterTransitionWrapper } from "@/contexts";
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
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const { encodedSort } = extractSortAndKey(resolvedSearchParams);
  const { filters, query } = extractFiltersAndQuery(resolvedSearchParams);
  const outputFilters = replaceFieldKey(filters, "inserted_at", "updated_at");

  // Check if the searchParams contain any date or scan filter
  const hasDateOrScan = hasDateOrScanFilter(resolvedSearchParams);

  // Check if there's a specific resource ID to fetch
  const resourceId = resolvedSearchParams.resourceId?.toString();

  const [metadataInfoData, providersData, resourceByIdData] = await Promise.all(
    [
      (hasDateOrScan ? getMetadataInfo : getLatestMetadataInfo)({
        query,
        filters: outputFilters,
        sort: encodedSort,
      }),
      getProviders({ pageSize: 50 }),
      resourceId
        ? getResourceById(resourceId, { include: ["provider"] })
        : Promise.resolve(null),
    ],
  );

  // Process the resource data to match the expected structure
  const processedResource = resourceByIdData?.data
    ? (() => {
        const resource = resourceByIdData.data;
        const providerDict = createDict("providers", resourceByIdData);

        const provider = {
          data: providerDict[resource.relationships?.provider?.data?.id],
        };

        return {
          ...resource,
          relationships: {
            ...resource.relationships,
            provider,
          },
        } as ResourceProps;
      })()
    : null;

  // Extract unique regions, services, groups from the metadata endpoint
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];
  const uniqueServices = metadataInfoData?.data?.attributes?.services || [];
  const uniqueGroups = metadataInfoData?.data?.attributes?.groups || [];

  return (
    <ContentLayout title="Resources" icon="lucide:warehouse">
      <FilterTransitionWrapper>
        <div className="mb-6">
          <ResourcesFilters
            providers={providersData?.data || []}
            uniqueRegions={uniqueRegions}
            uniqueServices={uniqueServices}
            uniqueGroups={uniqueGroups}
          />
        </div>
        <Suspense fallback={<SkeletonTableResources />}>
          <SSRDataTable searchParams={resolvedSearchParams} />
        </Suspense>
      </FilterTransitionWrapper>
      {processedResource && (
        <ResourceDetailsSheet resource={processedResource} />
      )}
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
      "groups",
      "provider",
      "inserted_at",
      "updated_at",
      "uid",
      "partition",
      "details",
      "metadata",
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
        <div className="text-small mb-4 flex rounded-lg border border-red-500 bg-red-100 p-2 text-red-700">
          <p className="mr-2 font-semibold">Error:</p>
          <p>{resourcesData.errors[0].detail}</p>
        </div>
      )}
      <ResourcesTableWithSelection
        data={expandedResources || []}
        metadata={resourcesData?.meta}
      />
    </>
  );
};
