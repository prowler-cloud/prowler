import { Spacer } from "@nextui-org/react";
import { format, parseISO } from "date-fns";
import { Suspense } from "react";

import { getResourceFields, getResources } from "@/actions/resources";
import { getScans } from "@/actions/scans";
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
  replaceFilterFieldKey,
} from "@/lib";
import { ResourceProps, SearchParamsProps } from "@/types";

export default async function Resources({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  // Check if the searchParams contain any date or filter
  const hasDateOrScan = hasDateOrScanFilter(searchParams);

  const { filters } = extractFiltersAndQuery(searchParams);
  filters["page[size]"] = "100"; // TODO: Remove page[size] 100 when metadata endpoint implemented

  if (!hasDateOrScan) {
    const scansData = await getScans({
      filters: {
        "fields[scans]": "inserted_at",
      },
    });

    if (scansData?.data?.length !== 0) {
      const latestScandate = scansData.data?.[0]?.attributes?.inserted_at;
      const formattedDate = format(parseISO(latestScandate), "yyyy-MM-dd");
      filters["filter[updated_at]"] = formattedDate;
    }
  }

  const outputFilters = replaceFilterFieldKey(
    filters,
    "inserted_at",
    "updated_at",
  );

  // Resource call for filters
  const resourcesData = await getResourceFields(
    "name,type,region,service",
    outputFilters,
  );

  let resourceNameList: string[] = [];
  let typeList: string[] = [];
  let regionList: string[] = [];
  let serviceList: string[] = [];

  if (resourcesData?.data) {
    resourceNameList = Array.from(
      new Set(
        resourcesData.data.map((item: ResourceProps) => item.attributes.name) ||
          [],
      ),
    );

    typeList = Array.from(
      new Set(
        resourcesData.data.map((item: ResourceProps) => item.attributes.type) ||
          [],
      ),
    );

    regionList = Array.from(
      new Set(
        resourcesData.data.map(
          (item: ResourceProps) => item.attributes.region,
        ) || [],
      ),
    );

    serviceList = Array.from(
      new Set(
        resourcesData.data.map(
          (item: ResourceProps) => item.attributes.service,
        ) || [],
      ),
    );
  }

  return (
    <ContentLayout title="Resources" icon="carbon:data-view">
      <FilterControls search date />
      <Spacer y={8} />
      <DataTableFilterCustom
        filters={[
          {
            key: "name",
            labelCheckboxGroup: "Resources",
            values: resourceNameList,
          },
          {
            key: "region",
            labelCheckboxGroup: "Region",
            values: regionList,
          },
          {
            key: "type",
            labelCheckboxGroup: "Type",
            values: typeList,
          },
          {
            key: "service",
            labelCheckboxGroup: "Service",
            values: serviceList,
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
  const defaultSort = "name";
  const { encodedSort } = extractSortAndKey({
    ...searchParams,
    sort: searchParams.sort ?? defaultSort,
  });

  // Check if the searchParams contain any date or filter
  const hasDateOrScan = hasDateOrScanFilter(searchParams);

  const { filters, query } = extractFiltersAndQuery(searchParams);

  if (!hasDateOrScan) {
    // Fetch scans data latest date
    const scansData = await getScans({
      filters: {
        "fields[scans]": "inserted_at",
      },
    });

    if (scansData?.data?.length !== 0) {
      const latestScandate = scansData?.data?.[0]?.attributes?.inserted_at;
      const formattedDate = format(parseISO(latestScandate), "yyyy-MM-dd");
      filters["filter[updated_at]"] = formattedDate;
    }
  }

  const outputFilters = replaceFilterFieldKey(
    filters,
    "inserted_at",
    "updated_at",
  );
  const resourcesData = await getResources({
    query,
    page,
    filters: outputFilters,
    sort: encodedSort,
    pageSize,
  });

  const findingsDict = createDict("findings", resourcesData);
  const providerDict = createDict("providers", resourcesData);

  // Expand each resources with its corresponding findings and provider
  const expandedResources = resourcesData?.data
    ? resourcesData.data.map((resource: ResourceProps) => {
        const findings = {
          meta: resource.relationships.findings.meta,
          data: resource.relationships.findings.data?.map(
            (finding) => findingsDict[finding.id],
          ),
        };

        const provider = {
          data: providerDict[resource.relationships.provider.data.id],
        };

        return {
          ...resource,
          relationships: { findings, provider },
        };
      })
    : [];

  const expandedResponse = {
    ...resourcesData,
    data: expandedResources,
  };

  return (
    <DataTable
      columns={ColumnResources}
      data={expandedResponse?.data || []}
      metadata={resourcesData?.meta}
    />
  );
};
