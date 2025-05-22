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
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
} from "@/lib";
import { ProviderAccountProps, ProviderProps } from "@/types";
import { FindingProps, ScanProps, SearchParamsProps } from "@/types/components";

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
    getScans({}),
  ]);

  // Extract unique regions and services from the new endpoint
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];
  const uniqueServices = metadataInfoData?.data?.attributes?.services || [];
  const uniqueResourceTypes =
    metadataInfoData?.data?.attributes?.resource_types || [];

  // Extract provider UIDs
  const providerUIDs: string[] = Array.from(
    new Set(
      providersData?.data
        ?.map((provider: ProviderProps) => provider.attributes?.uid)
        .filter(Boolean),
    ),
  );

  const providerDetails: Array<{ [uid: string]: ProviderAccountProps }> =
    providerUIDs.map((uid) => {
      const provider = providersData.data.find(
        (p: { attributes: { uid: string } }) => p.attributes?.uid === uid,
      );

      return {
        [uid]: {
          provider: provider?.attributes?.provider || "",
          uid: uid,
          alias: provider?.attributes?.alias ?? null,
        },
      };
    });

  // Extract scan UUIDs with "completed" state and more than one resource
  const completedScans = scansData?.data
    ?.filter(
      (scan: ScanProps) =>
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
    <ContentLayout title="Findings" icon="carbon:data-view-alt">
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
            key: "resource_type__in",
            labelCheckboxGroup: "Resource Type",
            values: uniqueResourceTypes,
          },
          {
            key: "provider_uid__in",
            labelCheckboxGroup: "Provider UID",
            values: providerUIDs,
            valueLabelMapping: providerDetails,
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
