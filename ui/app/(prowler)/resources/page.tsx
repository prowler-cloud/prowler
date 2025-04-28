import { Spacer } from "@nextui-org/react";
import { format, parseISO, subDays } from "date-fns";
import { Suspense } from "react";

import { getResourceFields, getResources } from "@/actions/resources";
import { getScansByFields } from "@/actions/scans";
import { FilterControls } from "@/components/filters";
import { ColumnResources } from "@/components/resources/table/column-resources";
import { SkeletonTableResources } from "@/components/resources/skeleton/skeleton-table-resources";
import { ContentLayout } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { createDict } from "@/lib";
import { ResourceProps, SearchParamsProps } from "@/types";

export default async function Resources({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});
  const twoDaysAgo = format(subDays(new Date(), 2), "yyyy-MM-dd");

  // Check if the searchParams contain any date or filter
  const hasDateOrScanFilter = Object.keys(searchParams).some((key) =>
    key.includes("inserted_at"),
  );

  // Default filters for getFindings
  const defaultFilters: Record<string, string> = hasDateOrScanFilter
    ? {} // Do not apply default filters if there are date or filters
    : { "filter[inserted_at]": twoDaysAgo, "page[size]": "100" }; // TODO: Remove page[size] 100 when metadata endpoint implemented 

  const filters: Record<string, string> = {
    ...defaultFilters,
    ...Object.fromEntries(
      Object.entries(searchParams)
        .filter(([key]) => key.startsWith("filter["))
        .map(([key, value]) => [
          key,
          Array.isArray(value) ? value.join(",") : value?.toString() || "",
        ]),
    ),
  };

  // Fetch scans data latest date not fully done
  const scansData = await getScansByFields("inserted_at", {
    "filter[state]": "completed",
  });

  if (scansData.data?.length !== 0) {
    const latestScandate = scansData.data[0].attributes.inserted_at;
    const formattedDate = format(parseISO(latestScandate), "yyyy-MM-dd");
    if (!hasDateOrScanFilter) {
      filters["filter[inserted_at]"] = formattedDate;
    }
  }

  const resourcesData = await getResourceFields(
    "name,type,region,service",
    filters,
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

  const defaultSort = "name";
  const sort = searchParams.sort?.toString() || defaultSort;

  const twoDaysAgo = format(subDays(new Date(), 2), "yyyy-MM-dd");

  // Check if the searchParams contain any date or filter
  const hasDateOrScanFilter = Object.keys(searchParams).some((key) =>
    key.includes("inserted_at"),
  );

  // Default filters for getFindings
  const defaultFilters: Record<string, string> = hasDateOrScanFilter
    ? {} // Do not apply default filters if there are date or filters
    : { "filter[inserted_at]": twoDaysAgo };

  const filters: Record<string, string> = {
    ...defaultFilters,
    ...Object.fromEntries(
      Object.entries(searchParams)
        .filter(([key]) => key.startsWith("filter["))
        .map(([key, value]) => [
          key,
          Array.isArray(value) ? value.join(",") : value?.toString() || "",
        ]),
    ),
  };

  // Fetch scans data latest date
  const scansData = await getScansByFields("inserted_at", {
    "filter[state]": "completed",
  });

  if (scansData.data?.length !== 0) {
    const latestScandate = scansData.data[0].attributes.inserted_at;
    const formattedDate = format(parseISO(latestScandate), "yyyy-MM-dd");
    if (!hasDateOrScanFilter) {
      filters["filter[inserted_at]"] = formattedDate;
    }
  }

  const query = filters["filter[search]"] || "";
  const resourcesData = await getResources({
    query,
    page,
    filters,
    sort,
    pageSize: 10,
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
