import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { FilterControls, filterProviders } from "@/components/filters";
import { AddProvider } from "@/components/providers";
import {
  ColumnProviders,
  SkeletonTableProviders,
} from "@/components/providers/table";
import { Header } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { SearchParamsProps } from "@/types";

export default async function Providers({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="Providers" icon="fluent:cloud-sync-24-regular" />

      <Spacer y={4} />
      <FilterControls search providers />
      <Spacer y={8} />
      <AddProvider />
      <Spacer y={4} />
      <DataTableFilterCustom filters={filterProviders || []} />
      <Spacer y={8} />

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableProviders />}>
            <SSRDataTable searchParams={searchParams} />
          </Suspense>
        </div>
      </div>
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

  const providersData = await getProviders({ query, page, sort, filters });
  return (
    <DataTable
      columns={ColumnProviders}
      data={providersData?.data || []}
      metadata={providersData?.meta}
    />
  );
};
