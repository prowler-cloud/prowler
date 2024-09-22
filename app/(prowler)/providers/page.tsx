import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProviders } from "@/actions";
import { FilterControls } from "@/components/filters";
import { AddProviderModal } from "@/components/providers";
import {
  ColumnsProvider,
  DataTableProvider,
  SkeletonTableProvider,
} from "@/components/providers/table";
import { Header } from "@/components/ui";
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
      <Spacer y={4} />
      <div className="flex flex-col items-end w-full">
        <div className="flex space-x-6">
          <AddProviderModal />
        </div>
        <Spacer y={6} />
        <Suspense key={searchParamsKey} fallback={<SkeletonTableProvider />}>
          <SSRDataTable searchParams={searchParams} />
        </Suspense>
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
  const sort = searchParams.sort?.toString() || "";

  // Extract all filter parameters
  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  );

  // Extract query from filters
  const query = (filters["filter[search]"] as string) || "";

  const providersData = await getProviders({ query, page, sort, filters });

  return (
    <DataTableProvider
      columns={ColumnsProvider}
      data={providersData?.data || []}
      metadata={providersData?.meta}
    />
  );
};
