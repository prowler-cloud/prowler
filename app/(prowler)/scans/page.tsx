import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { FilterControls, filterScans } from "@/components/filters";
import { ColumnScans, SkeletonTableScans } from "@/components/scans/table";
import { Header } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { SearchParamsProps } from "@/types";

export default async function Scans({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="Scans" icon="lucide:scan-search" />

      <Spacer y={4} />
      <FilterControls search date providers />
      <Spacer y={4} />

      <div className="grid grid-cols-12 items-end gap-4">
        <div className="col-span-12 lg:col-span-4">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
            <SSRDataTableProviders searchParams={searchParams} />
          </Suspense>
        </div>
        <div className="col-span-12 lg:col-span-8">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
            <SSRDataTableScans searchParams={searchParams} />
          </Suspense>
        </div>
      </div>
    </>
  );
}

const SSRDataTableProviders = async ({
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

  const providersData = await getProviders({ query, page, sort, filters });

  return (
    <DataTable
      columns={ColumnScans}
      data={providersData?.data || []}
      metadata={providersData?.meta}
      // customFilters={filterProviders}
    />
  );
};

const SSRDataTableScans = async ({
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

  const providersData = await getProviders({ query, page, sort, filters });

  return (
    <DataTable
      columns={ColumnScans}
      data={providersData?.data || []}
      metadata={providersData?.meta}
      customFilters={filterScans}
    />
  );
};
