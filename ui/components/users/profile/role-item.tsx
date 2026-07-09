"use client";

import { Ban, Check } from "lucide-react";

import { Badge, Card } from "@/components/shadcn";
import { getRolePermissions } from "@/lib/permissions";
import { RoleData, RoleDetail } from "@/types/users";

interface PermissionItemProps {
  enabled: boolean;
  label: string;
}

export const PermissionIcon = ({ enabled }: { enabled: boolean }) => (
  <span
    className={`inline-flex h-4 w-4 items-center justify-center rounded-full ${enabled ? "bg-green-100 text-green-700" : "bg-red-100 text-red-500"}`}
  >
    {enabled ? <Check /> : <Ban />}
  </span>
);

const PermissionItem = ({ enabled, label }: PermissionItemProps) => (
  <div className="flex items-center gap-2 whitespace-nowrap">
    <PermissionIcon enabled={enabled} />
    <span className="text-xs">{label}</span>
  </div>
);

export const RoleItem = ({
  role,
  roleDetail,
}: {
  role: RoleData;
  roleDetail?: RoleDetail;
}) => {
  if (!roleDetail) {
    return (
      <Badge key={role.id} variant="info">
        {role.id}
      </Badge>
    );
  }

  const { attributes } = roleDetail;
  const roleName = attributes?.name || role.id;
  const permissionState = attributes?.permission_state || "";
  const detailsId = `role-details-${role.id}`;

  const permissions = getRolePermissions(attributes);

  return (
    <Card variant="inner">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge variant="info">{roleName}</Badge>
          {permissionState && (
            <Badge variant="tag" className="capitalize">
              {permissionState}
            </Badge>
          )}
        </div>
      </div>

      <div
        id={detailsId}
        className="border-border-neutral-primary border-t pt-4"
        role="region"
        aria-label={`Details for role ${roleName}`}
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-2">
          {permissions.map(({ key, label, enabled }) => (
            <PermissionItem key={key} label={label} enabled={enabled} />
          ))}
        </div>
      </div>
    </Card>
  );
};
