import { Spacer } from "@nextui-org/react";
import React, { Suspense } from "react";

import { getFindings } from "@/actions/findings";
import { filterFindings } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import {
  ColumnFindings,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { Header } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib";
import { FindingProps, SearchParamsProps } from "@/types/components";

export default async function Findings({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="Findings" icon="ph:list-checks-duotone" />
      <Spacer />
      <Spacer y={4} />
      <FilterControls search providers date />
      <Spacer y={4} />
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
  const resourceDict = createDict("Resource", findingsData);
  const scanDict = createDict("Scan", findingsData);
  const providerDict = createDict("Provider", findingsData);

  // Expand each finding with its corresponding resource, scan, and provider
  const expandedFindings = findingsData.data.map((finding: FindingProps) => {
    const scan = scanDict[finding.relationships?.scan?.data?.id];
    const resource =
      resourceDict[finding.relationships?.resources?.data?.[0]?.id];
    const provider = providerDict[resource?.relationships?.provider?.data?.id];

    return {
      ...finding,
      relationships: { scan, resource, provider },
    };
  });

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
      customFilters={filterFindings}
    />
  );
};
