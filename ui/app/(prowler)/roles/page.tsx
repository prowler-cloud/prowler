import Link from "next/link";
import { Suspense } from "react";

import { getRoles } from "@/actions/roles";
import { FilterControls } from "@/components/filters";
import { filterRoles } from "@/components/filters/data-filters";
import { AddIcon } from "@/components/icons";
import { ColumnsRoles, SkeletonTableRoles } from "@/components/roles/table";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { SearchParamsProps } from "@/types";

export default async function Roles({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

  return (
    <ContentLayout title="Roles" icon="lucide:user-cog">
      <FilterControls search />

      <div className="flex flex-col gap-6">
        <div className="flex flex-row items-end justify-between">
          <DataTableFilterCustom filters={filterRoles || []} />
          <Button asChild>
            <Link href="/roles/new">
              Add Role
              <AddIcon size={20} />
            </Link>
          </Button>
        </div>

        <Suspense key={searchParamsKey} fallback={<SkeletonTableRoles />}>
          <SSRDataTable searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
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
      key={`roles-${Date.now()}`}
      columns={ColumnsRoles}
      data={rolesData?.data || []}
      metadata={rolesData?.meta}
    />
  );
};
