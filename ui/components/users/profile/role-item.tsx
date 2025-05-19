"use client";

import { Chip } from "@nextui-org/react";
import { Ban, Check } from "lucide-react";
import { useState } from "react";

import { Role, RoleDetail } from "@/types/users/users";

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
  <div className="flex items-center space-x-2 whitespace-nowrap">
    <PermissionIcon enabled={enabled} />
    <span className="text-xs">{label}</span>
  </div>
);

export const RoleItem = ({
  role,
  roleDetail,
}: {
  role: Role;
  roleDetail?: RoleDetail;
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

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

  const permissions = [
    {
      key: "manage_users",
      label: "Manage Users",
      enabled: attributes.manage_users,
    },
    {
      key: "manage_account",
      label: "Manage Account",
      enabled: attributes.manage_account,
    },
    {
      key: "manage_providers",
      label: "Manage Providers",
      enabled: attributes.manage_providers,
    },
    {
      key: "manage_scans",
      label: "Manage Scans",
      enabled: attributes.manage_scans,
    },

    {
      key: "manage_integrations",
      label: "Manage Integrations",
      enabled: attributes.manage_integrations,
    },
    {
      key: "unlimited_visibility",
      label: "Unlimited Visibility",
      enabled: attributes.unlimited_visibility,
    },
  ];

  return (
    <div className="rounded-lg bg-gray-50 p-2 dark:bg-gray-800">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Chip size="sm" variant="flat" color="primary">
            {roleName}
          </Chip>
          <span className="text-xs capitalize text-gray-500">
            {permissionState}
          </span>
        </div>
        <button
          className="rounded text-xs text-blue-500 hover:text-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1"
          onClick={() => setIsExpanded(!isExpanded)}
          aria-expanded={isExpanded}
          aria-controls={detailsId}
          type="button"
        >
          {isExpanded ? "Hide Details" : "Show Details"}
        </button>
      </div>

      {isExpanded && (
        <div
          id={detailsId}
          className="animate-fadeIn mt-3 border-t pt-3"
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
    </div>
  );
};
