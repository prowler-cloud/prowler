"use client";

import { Chip } from "@nextui-org/react";
import { ReactNode } from "react";

interface IntegrationCardHeaderProps {
  icon: ReactNode;
  title: string;
  subtitle?: string;
  chips?: Array<{
    label: string;
    color?: "default" | "primary" | "secondary" | "success" | "warning" | "danger";
    variant?: "solid" | "bordered" | "light" | "flat" | "faded" | "shadow";
  }>;
  connectionStatus?: {
    connected: boolean;
    label?: string;
  };
}

export const IntegrationCardHeader = ({
  icon,
  title,
  subtitle,
  chips = [],
  connectionStatus,
}: IntegrationCardHeaderProps) => {
  return (
    <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        {icon}
        <div>
          <h4 className="text-md font-semibold">{title}</h4>
          {subtitle && (
            <p className="text-xs text-gray-500 dark:text-gray-300">
              {subtitle}
            </p>
          )}
        </div>
      </div>
      {(chips.length > 0 || connectionStatus) && (
        <div className="flex flex-wrap items-center gap-2">
          {chips.map((chip, index) => (
            <Chip
              key={index}
              size="sm"
              variant={chip.variant || "flat"}
              color={chip.color || "default"}
              className="text-xs"
            >
              {chip.label}
            </Chip>
          ))}
          {connectionStatus && (
            <Chip
              size="sm"
              color={connectionStatus.connected ? "success" : "danger"}
              variant="flat"
            >
              {connectionStatus.label ||
                (connectionStatus.connected ? "Connected" : "Disconnected")}
            </Chip>
          )}
        </div>
      )}
    </div>
  );
};