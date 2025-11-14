"use client";

import { Chip } from "@heroui/chip";
import { Ban, Check } from "lucide-react";
import { useState } from "react";

import { Button, Card } from "@/components/shadcn";
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
  const [isExpanded, setIsExpanded] = useState(true);

  if (!roleDetail) {
    return (
      <Chip key={role.id} size="sm" variant="flat" color="primary">
        {role.id}
      </Chip>
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
          <Chip size="sm" variant="flat" color="primary">
            {roleName}
          </Chip>
          <span className="text-xs text-gray-500 capitalize">
            {permissionState}
          </span>
        </div>

        <Button
          variant="ghost"
          size="sm"
          onClick={() => setIsExpanded(!isExpanded)}
        >
          {isExpanded ? "Hide details" : "Show details"}
        </Button>
      </div>

      {isExpanded && (
        <div
          id={detailsId}
          className="animate-fadeIn border-border-neutral-primary border-t pt-4"
          role="region"
          aria-label={`Details for role ${roleName}`}
        >
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-2">
            {permissions.map(({ key, label, enabled }) => (
              <PermissionItem key={key} label={label} enabled={enabled} />
            ))}
          </div>
        </div>
      )}
    </Card>
  );
};
