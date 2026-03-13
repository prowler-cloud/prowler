import { redirect } from "next/navigation";

import { SearchParamsProps } from "@/types";

export default async function ManageGroupsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const groupId = resolvedSearchParams.groupId;

  const target = groupId
    ? `/providers?tab=account-groups&groupId=${groupId}`
    : "/providers?tab=account-groups";

  redirect(target);
}
