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
import { SearchParamsProps } from "@/types/components";

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

  return (
    <DataTable
      columns={ColumnFindings}
      data={findingsData?.data || []}
      metadata={findingsData?.meta}
      customFilters={filterFindings}
    />
  );
};
