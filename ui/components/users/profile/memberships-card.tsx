import { Card, CardContent } from "@/components/shadcn";
import { MembershipDetailData, TenantDetailData } from "@/types/users";

import { MembershipItem } from "./membership-item";

export const MembershipsCard = ({
  memberships,
  tenantsMap,
  isOwner,
}: {
  memberships: MembershipDetailData[];
  tenantsMap: Record<string, TenantDetailData>;
  isOwner: boolean;
}) => {
  return (
    <Card variant="base" padding="none" className="p-4">
      <CardContent>
        <div className="mb-6 flex flex-col gap-1">
          <h4 className="text-lg font-bold">Organizations</h4>
          <p className="text-xs text-gray-500">
            Organizations this user is associated with
          </p>
        </div>
        {memberships.length === 0 ? (
          <div className="text-sm text-gray-500">No memberships found.</div>
        ) : (
          <div className="flex flex-col gap-2">
            {memberships.map((membership) => {
              const tenantId = membership.relationships.tenant.data.id;
              return (
                <MembershipItem
                  key={membership.id}
                  membership={membership}
                  tenantId={tenantId}
                  tenantName={tenantsMap[tenantId]?.attributes.name}
                  isOwner={isOwner}
                />
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
