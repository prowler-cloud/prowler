"use client";

import { Card } from "@nextui-org/react";
import React from "react";

import { permissionsData } from "@/lib";

const PermissionCard = ({
  title,
  description,
}: {
  title: string;
  description: string;
}) => (
  <Card className="shadow-box rounded-lg px-4 py-2 dark:bg-prowler-blue-400">
    <h3 className="text-md font-semibold text-gray-800 dark:text-prowler-theme-pale/90">
      {title}
    </h3>
    <p className="text-sm text-gray-600 dark:text-gray-400">{description}</p>
  </Card>
);

export const PermissionsInfo: React.FC = () => {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
      {permissionsData.map((permission) => {
        // Skip manage_billing permission if not in cloud environment
        if (
          permission.field === "manage_billing" &&
          process.env.NEXT_PUBLIC_IS_CLOUD_ENV !== "true"
        ) {
          return null;
        }

        return (
          <PermissionCard
            key={permission.field}
            title={permission.label}
            description={permission.description}
          />
        );
      })}
    </div>
  );
};
