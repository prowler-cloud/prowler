import Link from "next/link";
import { Suspense } from "react";

import { getInvitations } from "@/actions/invitations/invitation";
import { getRoles } from "@/actions/roles";
import { FilterControls } from "@/components/filters";
import { filterInvitations } from "@/components/filters/data-filters";
import { AddIcon } from "@/components/icons";
import {
  ColumnsInvitation,
  SkeletonTableInvitation,
} from "@/components/invitations/table";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { InvitationProps, Role, SearchParamsProps } from "@/types";

export default async function Invitations({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams || {});

  return (
    <ContentLayout title="Invitations" icon="lucide:mail">
      <FilterControls search />

      <div className="flex flex-col gap-6">
        <div className="flex flex-row items-end justify-between">
          <DataTableFilterCustom filters={filterInvitations || []} />

          <Button asChild>
            <Link href="/invitations/new">
              Send Invitation
              <AddIcon size={20} />
            </Link>
          </Button>
        </div>

        <Suspense key={searchParamsKey} fallback={<SkeletonTableInvitation />}>
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

  // Fetch invitations and roles
  const invitationsData = await getInvitations({
    query,
    page,
    sort,
    filters,
    pageSize,
  });
  const rolesData = await getRoles({});

  // Create a dictionary for roles by invitation ID
  const roleDict = (rolesData?.data || []).reduce(
    (acc: Record<string, Role>, role: Role) => {
      role.relationships.invitations.data.forEach((invitation: any) => {
        acc[invitation.id] = role;
      });
      return acc;
    },
    {},
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

  // Expand the invitations
  const expandedInvitations = invitationsData?.data?.map(
    (invitation: InvitationProps) => {
      const role = roleDict[invitation.id];

      return {
        ...invitation,
        relationships: {
          ...invitation.relationships,
          role,
        },
        roles, // Include all roles here for each invitation
      };
    },
  );

  // Create the expanded response
  const expandedResponse = {
    ...invitationsData,
    data: expandedInvitations,
    roles,
  };

  return (
    <DataTable
      key={Date.now()}
      columns={ColumnsInvitation}
      data={expandedResponse?.data || []}
      metadata={invitationsData?.meta}
    />
  );
};
