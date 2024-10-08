import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

// import { getProviders } from "@/actions/providers";
import { FilterControls, filterScans } from "@/components/filters";
import {
  // ColumnsProvider,
  // DataTableProvider,
  SkeletonTableProvider,
} from "@/components/providers/table";
import { Header } from "@/components/ui";
import { SearchParamsProps } from "@/types";

export default async function Scan({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="Scanners" icon="lucide:scan-search" />

      <Spacer y={4} />
      <FilterControls search date providers customFilters={filterScans} />
      <Spacer y={4} />

      <Suspense key={searchParamsKey} fallback={<SkeletonTableProvider />}>
        {/* <SSRDataTable searchParams={searchParams} /> */}
      </Suspense>
    </>
  );
}

// const SSRDataTable = async ({
//   searchParams,
// }: {
//   searchParams: SearchParamsProps;
// }) => {
//   const page = parseInt(searchParams.page?.toString() || "1", 10);
//   const sort = searchParams.sort?.toString();

//   // Extract all filter parameters
//   const filters = Object.fromEntries(
//     Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
//   );

//   // Extract query from filters
//   const query = (filters["filter[search]"] as string) || "";

//   const providersData = await getProviders({ query, page, sort, filters });

//   return (
//     <DataTableProvider
//       columns={ColumnsProvider}
//       data={providersData?.data || []}
//       metadata={providersData?.meta}
//     />
//   );
// };
