"use client";

import { ExternalLink } from "lucide-react";
import { ReactNode } from "react";

import { Badge } from "@/components/shadcn";
import { cn } from "@/lib/utils";

interface IntegrationCardHeaderProps {
  icon: ReactNode;
  title: string;
  subtitle?: string;
  chips?: Array<{
    label: string;
    className?: string;
  }>;
  connectionStatus?: {
    connected: boolean;
    label?: string;
  };
  navigationUrl?: string;
}

export const IntegrationCardHeader = ({
  icon,
  title,
  subtitle,
  chips = [],
  connectionStatus,
  navigationUrl,
}: IntegrationCardHeaderProps) => {
  return (
    <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        {icon}
        <div>
          <div className="flex items-center gap-2">
            <h4 className="text-md font-semibold">{title}</h4>
            {navigationUrl && (
              <a
                target="_blank"
                rel="noopener noreferrer"
                className="text-black dark:text-white"
                href={navigationUrl}
                aria-label="open bucket in new tab"
              >
                <ExternalLink size={16} />
              </a>
            )}
          </div>
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
            <Badge
              key={index}
              variant="outline"
              className={cn(
                "border-border-neutral-secondary bg-bg-neutral-secondary text-text-neutral-primary text-xs font-normal",
                chip.className,
              )}
            >
              {chip.label}
            </Badge>
          ))}
          {connectionStatus && (
            <Badge
              variant="outline"
              className={cn(
                "text-xs font-normal",
                connectionStatus.connected
                  ? "bg-bg-pass-secondary text-text-success-primary border-transparent"
                  : "bg-bg-danger-secondary text-text-danger border-transparent",
              )}
            >
              {connectionStatus.label ||
                (connectionStatus.connected ? "Connected" : "Disconnected")}
            </Badge>
          )}
        </div>
      )}
    </div>
  );
};
