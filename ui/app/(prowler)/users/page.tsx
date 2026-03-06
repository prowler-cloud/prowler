import Link from "next/link";
import { Suspense } from "react";

import { getRoles } from "@/actions/roles/roles";
import { getUsers } from "@/actions/users/users";
import { FilterControls } from "@/components/filters";
import { AddIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { ColumnsUser, SkeletonTableUser } from "@/components/users/table";
import { Role, SearchParamsProps, UserProps } from "@/types";

export default async function Users({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

  return (
    <ContentLayout title="Users" icon="lucide:user">
      <FilterControls search />

      <div className="flex flex-col gap-6">
        <div className="flex flex-row items-end justify-end">
          <Button asChild>
            <Link href="/invitations/new">
              Invite User
              <AddIcon size={20} />
            </Link>
          </Button>
        </div>

        <Suspense key={searchParamsKey} fallback={<SkeletonTableUser />}>
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

  const usersData = await getUsers({ query, page, sort, filters, pageSize });
  const rolesData = await getRoles({});

  // Create a dictionary for roles by user ID
  const roleDict = (usersData?.included || []).reduce(
    (acc: Record<string, any>, item: Role) => {
      if (item.type === "roles") {
        acc[item.id] = item.attributes;
      }
      return acc;
    },
    {} as Record<string, Role>,
  );

  // Generate the array of roles with all the roles available
  const roles = Array.from(
    new Map(
      (rolesData?.data || []).map((role: Role) => [
        role.id,
        { id: role.id, name: role.attributes?.name || "Unnamed Role" },
      ]),
    ).values(),
  );

  // Expand the users with their roles
  const expandedUsers = (usersData?.data || []).map((user: UserProps) => {
    // Check if the user has a role
    const roleId = user?.relationships?.roles?.data?.[0]?.id;
    const role = roleDict?.[roleId] || null;

    return {
      ...user,
      attributes: {
        ...(user?.attributes || {}),
        role,
      },
      roles,
    };
  });

  return (
    <DataTable
      key={`scans-${Date.now()}`}
      columns={ColumnsUser}
      data={expandedUsers || []}
      metadata={usersData?.meta}
    />
  );
};
