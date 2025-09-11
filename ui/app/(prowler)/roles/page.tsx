import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getRoles } from "@/actions/roles";
import { FilterControls } from "@/components/filters";
import { filterRoles } from "@/components/filters/data-filters";
import { AddRoleButton } from "@/components/roles";
import { ColumnsRoles } from "@/components/roles/table";
import { SkeletonTableRoles } from "@/components/roles/table";
import { ContentLayout } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { SearchParamsProps } from "@/types";

export default async function Roles({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <ContentLayout title="Roles" icon="mdi:account-key-outline">
      <FilterControls search />
      <Spacer y={8} />
      <AddRoleButton />
      <Spacer y={4} />
      <DataTableFilterCustom filters={filterRoles || []} />
      <Spacer y={8} />

      <Suspense key={searchParamsKey} fallback={<SkeletonTableRoles />}>
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
  const sort = searchParams.sort?.toString();
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);

  // Extract all filter parameters
  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  );

  // Extract query from filters
  const query = (filters["filter[search]"] as string) || "";

  const rolesData = await getRoles({ query, page, sort, filters, pageSize });

  return (
    <DataTable
      columns={ColumnsRoles}
      data={rolesData?.data || []}
      metadata={rolesData?.meta}
    />
  );
};
