import { Card, CardBody, CardHeader } from "@nextui-org/react";

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
    <Card className="dark:bg-prowler-blue-400">
      <CardHeader className="gap-2">
        <div className="flex flex-col gap-1">
          <h4 className="text-lg font-bold">Organizations</h4>
          <p className="text-xs text-gray-500">
            Organizations this user is associated with
          </p>
        </div>
      </CardHeader>
      <CardBody>
        {memberships.length === 0 ? (
          <div className="text-sm text-gray-500">No memberships found.</div>
        ) : (
          <div className="space-y-2">
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
      </CardBody>
    </Card>
  );
};
