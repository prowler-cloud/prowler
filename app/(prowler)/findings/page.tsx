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
import { FindingProps, SearchParamsProps } from "@/types/components";

export default async function Findings({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  return (
    <>
      <Header title="Findings" icon="ph:list-checks-duotone" />
      <Spacer />
      <Spacer y={4} />
      <FilterControls search providers date mutedFindings />
      <Spacer y={4} />
      <Suspense fallback={<SkeletonTableFindings />}>
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

  // Create dictionaries from the included data
  const resourceDict = Object.fromEntries(
    findingsData.included
      .filter((item: { type: string }) => item.type === "Resource")
      .map((resource: { id: string }) => [resource.id, resource]),
  );

  const scanDict = Object.fromEntries(
    findingsData.included
      .filter((item: { type: string }) => item.type === "Scan")
      .map((scan: { id: string }) => [scan.id, scan]),
  );

  const providerDict = Object.fromEntries(
    findingsData.included
      .filter((item: { type: string }) => item.type === "Provider")
      .map((provider: { id: string }) => [provider.id, provider]),
  );

  // Enrich each finding with its corresponding resource, scan, and provider
  const enrichedFindings = findingsData.data.map((finding: FindingProps) => {
    const scanId = finding.relationships?.scan?.data?.id;
    // eslint-disable-next-line security/detect-object-injection
    const scan = scanId ? scanDict[scanId] : undefined;

    const resourceId = finding.relationships?.resources?.data?.[0]?.id;
    console.log(resourceId, "resourceId");
    const resource =
      resourceId && resourceDict ? resourceDict[resourceId] : undefined;

    const providerId = resource?.relationships?.provider?.data?.id;
    // eslint-disable-next-line security/detect-object-injection
    const provider = providerId ? providerDict[providerId] : undefined;

    return {
      ...finding,
      relationships: {
        scan: scan,
        resource: resource,
        provider: provider,
      },
    };
  });

  // Create the new object while maintaining the original structure
  const enrichedResponse = {
    ...findingsData,
    data: enrichedFindings,
  };

  return (
    <DataTable
      columns={ColumnFindings}
      data={enrichedResponse?.data || []}
      metadata={findingsData?.meta}
      customFilters={filterFindings}
    />
  );
};
