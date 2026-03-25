import { MembershipDetailData, TenantDetailData } from "@/types/users";

import { MembershipsCardClient } from "./memberships-card-client";

export const MembershipsCard = ({
  memberships,
  tenantsMap,
  isOwner,
  hasManageAccount,
  sessionTenantId,
}: {
  memberships: MembershipDetailData[];
  tenantsMap: Record<string, TenantDetailData>;
  isOwner: boolean;
  hasManageAccount: boolean;
  sessionTenantId: string | undefined;
}) => {
  return (
    <MembershipsCardClient
      memberships={memberships}
      tenantsMap={tenantsMap}
      isOwner={isOwner}
      hasManageAccount={hasManageAccount}
      sessionTenantId={sessionTenantId}
    />
  );
};
