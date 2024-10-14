import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import {
  FilterControls,
  filterProviders,
  filterScans,
} from "@/components/filters";
import { SkeletonTableScans } from "@/components/scans/table";
import { ColumnProviderScans } from "@/components/scans/table/provider-scans";
import { ColumnGetScans } from "@/components/scans/table/scans";
import { ColumnGetScansSchedule } from "@/components/scans/table/schedule-scans";
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
      <Spacer y={8} />

      <div className="grid grid-cols-12 items-start gap-4">
        <div className="col-span-12 lg:col-span-4">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
            <SSRDataTableProviders />
          </Suspense>
        </div>
        <div className="col-span-12 lg:col-span-6">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
            <SSRDataTableScansSchedule searchParams={searchParams} />
          </Suspense>
        </div>
        <div className="col-span-12">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
            <SSRDataTableScans searchParams={searchParams} />
          </Suspense>
        </div>
      </div>
    </>
  );
}

const SSRDataTableProviders = async () => {
  // const page = parseInt(searchParams.page?.toString() || "1", 10);
  // const sort = searchParams.sort?.toString();

  // Extract all filter parameters
  // const filters = Object.fromEntries(
  //   Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  // );

  // Extract query from filters
  // const query = (filters["filter[search]"] as string) || "";

  const providersData = await getProviders({ page: 1 });

  return (
    <DataTable
      columns={ColumnProviderScans}
      data={providersData?.data || []}
      metadata={providersData?.meta}
      customFilters={filterProviders}
    />
  );
};

const SSRDataTableScansSchedule = async ({
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

  const scansData = await getScans({ query, page, sort, filters });

  return (
    <DataTable
      columns={ColumnGetScansSchedule}
      data={scansData?.data || []}
      metadata={scansData?.meta}
      customFilters={filterScans}
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

  const scansData = await getScans({ query, page, sort, filters });

  return (
    <DataTable
      columns={ColumnGetScans}
      data={scansData?.data || []}
      metadata={scansData?.meta}
      customFilters={filterScans}
    />
  );
};
