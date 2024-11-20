import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getInvitations } from "@/actions/invitations/invitation";
import { FilterControls } from "@/components/filters";
import { filterInvitations } from "@/components/filters/data-filters";
import { SendInvitationButton } from "@/components/invitations";
import {
  ColumnsInvitation,
  SkeletonTableInvitation,
} from "@/components/invitations/table";
import { Header } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { SearchParamsProps } from "@/types";

export default async function Invitations({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="Invitations" icon="ci:users" />
      <Spacer y={4} />
      <FilterControls search />
      <Spacer y={8} />
      <SendInvitationButton />
      <Spacer y={4} />
      <DataTableFilterCustom filters={filterInvitations || []} />
      <Spacer y={8} />

      <Suspense key={searchParamsKey} fallback={<SkeletonTableInvitation />}>
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

  const invitationsData = await getInvitations({ query, page, sort, filters });

  return (
    <DataTable
      columns={ColumnsInvitation}
      data={invitationsData?.data || []}
      metadata={invitationsData?.meta}
    />
  );
};
