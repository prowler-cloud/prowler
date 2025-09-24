import { Card, CardBody, CardHeader } from "@nextui-org/react";

import { RoleData, RoleDetail } from "@/types/users";

import { RoleItem } from "./role-item";

export const RolesCard = ({
  roles,
  roleDetails,
}: {
  roles: RoleData[];
  roleDetails: Record<string, RoleDetail>;
}) => {
  return (
    <Card className="dark:bg-prowler-blue-400">
      <CardHeader className="gap-2">
        <div className="flex flex-col gap-1">
          <h4 className="text-lg font-bold">Active roles</h4>
          <p className="text-xs text-gray-500">
            Roles assigned to this user account
          </p>
        </div>
      </CardHeader>
      <CardBody>
        {roles.length === 0 ? (
          <div className="text-sm text-gray-500">No roles assigned.</div>
        ) : (
          <div className="space-y-2">
            {roles.map((role) => (
              <RoleItem
                key={role.id}
                role={role}
                roleDetail={roleDetails[role.id]}
              />
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
};
