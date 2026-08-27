"use client";

import { ExternalLink } from "lucide-react";
import { ReactNode } from "react";

import { Badge } from "@/components/shadcn";
import { cn } from "@/lib/utils";

// `null` means never checked, not disconnected: it must not get the fail tokens.
const CONNECTION_BADGE = {
  connected: {
    label: "Connected",
    className:
      "bg-bg-pass-secondary text-text-success-primary border-transparent",
  },
  disconnected: {
    label: "Disconnected",
    className:
      "bg-bg-fail-secondary text-text-error-primary border-transparent",
  },
  unchecked: {
    label: "Not checked yet",
    className: "border-border-tag bg-bg-tag text-text-neutral-secondary",
  },
} as const;

type ConnectionBadgeState = keyof typeof CONNECTION_BADGE;

const connectionBadgeState = (
  connected: boolean | null,
): ConnectionBadgeState =>
  connected === null ? "unchecked" : connected ? "connected" : "disconnected";

interface IntegrationCardChip {
  label: string;
  className?: string;
}

interface IntegrationConnectionStatus {
  connected: boolean | null;
  label?: string;
}

interface IntegrationCardHeaderProps {
  icon: ReactNode;
  title: string;
  subtitle?: string;
  chips?: IntegrationCardChip[];
  connectionStatus?: IntegrationConnectionStatus;
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
  const badgeState = connectionStatus
    ? connectionBadgeState(connectionStatus.connected)
    : null;
  const badge = badgeState ? CONNECTION_BADGE[badgeState] : null;

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
      {(chips.length > 0 || badge) && (
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
          {badge && badgeState && (
            <Badge
              variant="outline"
              data-connection-status={badgeState}
              className={cn("text-xs font-normal", badge.className)}
            >
              {connectionStatus?.label || badge.label}
            </Badge>
          )}
        </div>
      )}
    </div>
  );
};
