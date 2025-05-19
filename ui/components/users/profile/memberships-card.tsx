import { Card, CardBody, CardHeader } from "@nextui-org/react";

import { MembershipDetailData } from "@/types/users/users";

import { MembershipItem } from "./membership-item";

export const MembershipsCard = ({
  memberships,
}: {
  memberships: MembershipDetailData[];
}) => {
  return (
    <Card className="dark:bg-prowler-blue-400">
      <CardHeader className="gap-2">
        <div className="flex flex-col gap-1">
          <h4 className="text-lg font-bold">Account Memberships</h4>
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
              <MembershipItem key={membership.id} membership={membership} />
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
};
