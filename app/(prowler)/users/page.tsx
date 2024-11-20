import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getUsers } from "@/actions/users/users";
import { FilterControls } from "@/components/filters";
import { filterUsers } from "@/components/filters/data-filters";
import { Header } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { AddUserButton } from "@/components/users";
import { ColumnsUser, SkeletonTableUser } from "@/components/users/table";
import { SearchParamsProps } from "@/types";

export default async function Users({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="Users" icon="ci:users" />
      <Spacer y={4} />
      <FilterControls search />
      <Spacer y={8} />
      <AddUserButton />
      <Spacer y={4} />
      <DataTableFilterCustom filters={filterUsers || []} />
      <Spacer y={8} />

      <Suspense key={searchParamsKey} fallback={<SkeletonTableUser />}>
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

  const usersData = await getUsers({ query, page, sort, filters });

  return (
    <DataTable
      columns={ColumnsUser}
      data={usersData?.data || []}
      metadata={usersData?.meta}
    />
  );
};
