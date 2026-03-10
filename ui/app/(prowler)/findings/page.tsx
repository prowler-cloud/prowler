import { Suspense } from "react";

import {
  getFindingById,
  getFindings,
  getLatestFindings,
  getLatestMetadataInfo,
  getMetadataInfo,
} from "@/actions/findings";
import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { FindingDetailsSheet } from "@/components/findings";
import { FindingsFilters } from "@/components/findings/findings-filters";
import {
  FindingsTableWithSelection,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { ContentLayout } from "@/components/ui";
import { FilterTransitionWrapper } from "@/contexts";
import {
  createDict,
  createScanDetailsMapping,
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
} from "@/lib";
import {
  createProviderDetailsMappingById,
  extractProviderIds,
} from "@/lib/provider-helpers";
import { ScanEntity, ScanProps } from "@/types";
import { FindingProps, SearchParamsProps } from "@/types/components";

export default async function Findings({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const { encodedSort } = extractSortAndKey(resolvedSearchParams);
  const { filters, query } = extractFiltersAndQuery(resolvedSearchParams);

  // Check if the searchParams contain any date or scan filter
  const hasDateOrScan = hasDateOrScanFilter(resolvedSearchParams);

  // Check if there's a specific finding ID to fetch
  const findingId = resolvedSearchParams.id?.toString();

  const [metadataInfoData, providersData, scansData, findingByIdData] =
    await Promise.all([
      (hasDateOrScan ? getMetadataInfo : getLatestMetadataInfo)({
        query,
        sort: encodedSort,
        filters,
      }),
      getProviders({ pageSize: 50 }),
      getScans({ pageSize: 50 }),
      findingId
        ? getFindingById(findingId, "resources,scan.provider")
        : Promise.resolve(null),
    ]);

  // Process the finding data to match the expected structure
  const processedFinding = findingByIdData?.data
    ? (() => {
        const finding = findingByIdData.data;
        const included = findingByIdData.included || [];

        // Build dictionaries from included data
        type IncludedItem = {
          type: string;
          id: string;
          attributes: Record<string, unknown>;
          relationships?: {
            provider?: { data?: { id: string } };
          };
        };

        const resourceDict: Record<string, unknown> = {};
        const scanDict: Record<string, IncludedItem> = {};
        const providerDict: Record<string, unknown> = {};

        included.forEach((item: IncludedItem) => {
          if (item.type === "resources") {
            resourceDict[item.id] = {
              id: item.id,
              attributes: item.attributes,
            };
          } else if (item.type === "scans") {
            scanDict[item.id] = item;
          } else if (item.type === "providers") {
            providerDict[item.id] = {
              id: item.id,
              attributes: item.attributes,
            };
          }
        });

        const scanId = finding.relationships?.scan?.data?.id;
        const resourceId = finding.relationships?.resources?.data?.[0]?.id;
        const scan = scanId ? scanDict[scanId] : undefined;
        const providerId = scan?.relationships?.provider?.data?.id;
        const resource = resourceId ? resourceDict[resourceId] : undefined;
        const provider = providerId ? providerDict[providerId] : undefined;

        return {
          ...finding,
          relationships: {
            scan: scan
              ? { data: scan, attributes: scan.attributes }
              : undefined,
            resource: resource,
            provider: provider,
          },
        } as FindingProps;
      })()
    : null;

  // Extract unique regions, services, categories, groups from the new endpoint
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];
  const uniqueServices = metadataInfoData?.data?.attributes?.services || [];
  const uniqueResourceTypes =
    metadataInfoData?.data?.attributes?.resource_types || [];
  const uniqueCategories = metadataInfoData?.data?.attributes?.categories || [];
  const uniqueGroups = metadataInfoData?.data?.attributes?.groups || [];

  // Extract provider IDs and details using helper functions
  const providerIds = providersData ? extractProviderIds(providersData) : [];
  const providerDetails = providersData
    ? createProviderDetailsMappingById(providerIds, providersData)
    : [];

  // Extract scan UUIDs with "completed" state and more than one resource
  const completedScans = scansData?.data?.filter(
    (scan: ScanProps) =>
      scan.attributes.state === "completed" &&
      scan.attributes.unique_resource_count > 1,
  );

  const completedScanIds =
    completedScans?.map((scan: ScanProps) => scan.id) || [];

  const scanDetails = createScanDetailsMapping(
    completedScans || [],
    providersData,
  ) as { [uid: string]: ScanEntity }[];

  return (
    <ContentLayout title="Findings" icon="lucide:tag">
      <FilterTransitionWrapper>
        <div className="mb-6">
          <FindingsFilters
            providers={providersData?.data || []}
            providerIds={providerIds}
            providerDetails={providerDetails}
            completedScans={completedScans || []}
            completedScanIds={completedScanIds}
            scanDetails={scanDetails}
            uniqueRegions={uniqueRegions}
            uniqueServices={uniqueServices}
            uniqueResourceTypes={uniqueResourceTypes}
            uniqueCategories={uniqueCategories}
            uniqueGroups={uniqueGroups}
          />
        </div>
        <Suspense fallback={<SkeletonTableFindings />}>
          <SSRDataTable searchParams={resolvedSearchParams} />
        </Suspense>
      </FilterTransitionWrapper>
      {processedFinding && <FindingDetailsSheet finding={processedFinding} />}
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
        <div className="text-small mb-4 flex rounded-lg border border-red-500 bg-red-100 p-2 text-red-700">
          <p className="mr-2 font-semibold">Error:</p>
          <p>{findingsData.errors[0].detail}</p>
        </div>
      )}
      <FindingsTableWithSelection
        data={expandedResponse?.data || []}
        metadata={findingsData?.meta}
      />
    </>
  );
};
