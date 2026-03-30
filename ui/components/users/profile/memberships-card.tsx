import { MembershipDetailData, TenantDetailData } from "@/types/users";

import { MembershipsCardClient } from "./memberships-card-client";

export const MembershipsCard = ({
  memberships,
  tenantsMap,
  hasManageAccount,
  sessionTenantId,
}: {
  memberships: MembershipDetailData[];
  tenantsMap: Record<string, TenantDetailData>;
  hasManageAccount: boolean;
  sessionTenantId: string | undefined;
}) => {
  return (
    <MembershipsCardClient
      memberships={memberships}
      tenantsMap={tenantsMap}
      hasManageAccount={hasManageAccount}
      sessionTenantId={sessionTenantId}
    />
  );
};
