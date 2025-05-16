"use client";

import { Chip } from "@nextui-org/react";
import { useState } from "react";

import { RoleData, RoleDetailData } from "@/types/users/profile";

import { PermissionIcon } from "./permission-icon";

export const RoleCard = ({
  role,
  roleDetail,
}: {
  role: RoleData;
  roleDetail?: RoleDetailData;
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

  return (
    <div key={role.id} className="rounded-lg bg-gray-50 p-2 dark:bg-gray-800">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Chip size="sm" variant="flat" color="primary">
            {attributes?.name || role.id}
          </Chip>
          <span className="text-xs capitalize text-gray-500">
            {attributes?.permission_state || ""}
          </span>
        </div>
        <button
          className="text-sm text-blue-500 focus:outline-none"
          onClick={() => setIsExpanded(!isExpanded)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              setIsExpanded(!isExpanded);
            }
          }}
          aria-expanded={isExpanded}
          aria-controls={`role-details-${role.id}`}
        >
          {isExpanded ? "Hide Details" : "Show Details"}
        </button>
      </div>

      {isExpanded && (
        <div id={`role-details-${role.id}`} className="mt-3 border-t pt-3">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-2">
            <div className="flex items-center space-x-2 whitespace-nowrap">
              <PermissionIcon enabled={attributes.manage_users} />
              <span className="text-xs">Manage Users</span>
            </div>
            <div className="flex items-center space-x-2 whitespace-nowrap">
              <PermissionIcon enabled={attributes.manage_account} />
              <span className="text-xs">Manage Account</span>
            </div>
            <div className="flex items-center space-x-2 whitespace-nowrap">
              <PermissionIcon enabled={attributes.manage_providers} />
              <span className="text-xs">Manage Providers</span>
            </div>
            <div className="flex items-center space-x-2 whitespace-nowrap">
              <PermissionIcon enabled={attributes.manage_scans} />
              <span className="text-xs">Manage Scans</span>
            </div>
            {attributes.manage_integrations !== undefined && (
              <div className="flex items-center space-x-2 whitespace-nowrap">
                <PermissionIcon enabled={attributes.manage_integrations} />
                <span className="text-xs">Manage Integrations</span>
              </div>
            )}
            <div className="flex items-center space-x-2 whitespace-nowrap">
              <PermissionIcon enabled={attributes.unlimited_visibility} />
              <span className="text-xs">Unlimited Visibility</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
