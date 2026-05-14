import { Card, CardContent } from "@/components/shadcn";
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
    <Card variant="base" padding="none" className="p-4">
      <CardContent>
        <div className="mb-6 flex flex-col gap-1">
          <h4 className="text-lg font-bold">Active roles</h4>
          <p className="text-xs text-gray-500">
            Roles assigned to this user account
          </p>
        </div>
        {roles.length === 0 ? (
          <div className="text-sm text-gray-500">No roles assigned.</div>
        ) : (
          <div className="flex flex-col gap-2">
            {roles.map((role) => (
              <RoleItem
                key={role.id}
                role={role}
                roleDetail={roleDetails[role.id]}
              />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
