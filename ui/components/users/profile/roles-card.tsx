import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
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
    <Card variant="inner" padding="none" className="gap-4 p-4 md:p-5">
      <CardHeader>
        <div className="flex flex-col gap-1">
          <CardTitle>Active roles</CardTitle>
          <p className="text-xs text-gray-500">
            Roles assigned to this user account
          </p>
        </div>
      </CardHeader>
      <CardContent>
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
