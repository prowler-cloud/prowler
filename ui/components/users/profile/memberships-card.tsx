import { Card, CardBody, CardHeader } from "@nextui-org/react";

import { MembershipDetailData } from "@/types/users/users";

import { MembershipItem } from "./membership-item";

// Definir interfaz para Tenant
interface Tenant {
  type: string;
  id: string;
  attributes: {
    name: string;
  };
  relationships: {
    memberships: {
      meta: {
        count: number;
      };
      data: Array<{
        type: string;
        id: string;
      }>;
    };
  };
}

export const MembershipsCard = ({
  memberships,
  tenantsMap,
}: {
  memberships: MembershipDetailData[];
  tenantsMap: Record<string, Tenant>;
}) => {
  return (
    <Card className="dark:bg-prowler-blue-400">
      <CardHeader className="gap-2">
        <div className="flex flex-col gap-1">
          <h4 className="text-lg font-bold">Tenants</h4>
          <p className="text-xs text-gray-500">
            Tenants this user is associated with
          </p>
        </div>
      </CardHeader>
      <CardBody>
        {memberships.length === 0 ? (
          <div className="text-sm text-gray-500">No memberships found.</div>
        ) : (
          <div className="space-y-2">
            {memberships.map((membership) => (
              <MembershipItem
                key={membership.id}
                membership={membership}
                tenantName={
                  tenantsMap[membership.relationships.tenant.data.id]
                    ?.attributes.name
                }
              />
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
};
