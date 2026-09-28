"use client";

import { ExternalLink } from "lucide-react";
import { ReactNode } from "react";

import { Badge } from "@/components/shadcn";
import { cn } from "@/lib/utils";

// `null` means never checked, not disconnected: it must not get the fail tokens.
const CONNECTION_BADGE = {
  connected: {
    label: "Connected",
    variant: "success",
    dotClassName: "bg-bg-pass",
  },
  disconnected: {
    label: "Disconnected",
    variant: "error",
    dotClassName: "bg-bg-fail",
  },
  unchecked: {
    label: "Not checked yet",
    variant: "tag",
    dotClassName: "bg-bg-data-muted",
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
  /**
   * A quiet third line under the subtitle, for a fact about the integration
   * rather than a claim about it — when its connection was last checked, say.
   */
  meta?: ReactNode;
  chips?: IntegrationCardChip[];
  connectionStatus?: IntegrationConnectionStatus;
  navigationUrl?: string;
  /** The integration's own controls, pinned to the end of the row. */
  actions?: ReactNode;
}

export const IntegrationCardHeader = ({
  icon,
  title,
  subtitle,
  meta,
  chips = [],
  connectionStatus,
  navigationUrl,
  actions,
}: IntegrationCardHeaderProps) => {
  const badgeState = connectionStatus
    ? connectionBadgeState(connectionStatus.connected)
    : null;
  const badge = badgeState ? CONNECTION_BADGE[badgeState] : null;

  // The end of the row belongs to the controls wherever there are any, so the
  // status travels with the name it qualifies instead of across the card.
  const statusBesideTitle = Boolean(actions);

  const statusBadge =
    badge && badgeState ? (
      <Badge variant={badge.variant} data-connection-status={badgeState}>
        <span
          aria-hidden="true"
          className={cn("size-1.5 rounded-full", badge.dotClassName)}
        />
        {connectionStatus?.label || badge.label}
      </Badge>
    ) : null;

  const hasAside =
    chips.length > 0 || Boolean(actions) || (statusBadge && !statusBesideTitle);

  return (
    <div className="flex w-full flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        {icon}
        <div className="flex min-w-0 flex-col gap-0.5">
          <div className="flex flex-wrap items-center gap-2">
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
            {statusBesideTitle && statusBadge}
          </div>
          {subtitle && (
            <p className="text-text-neutral-tertiary text-xs">{subtitle}</p>
          )}
          {meta}
        </div>
      </div>
      {hasAside && (
        <div className="flex flex-wrap items-center gap-2">
          {chips.map((chip, index) => (
            <Badge
              key={index}
              variant="outline"
              // Weight left to the Badge, so a chip and the status pill beside
              // it are never set differently.
              className={cn(
                "border-border-neutral-secondary bg-bg-neutral-secondary text-text-neutral-primary text-xs",
                chip.className,
              )}
            >
              {chip.label}
            </Badge>
          ))}
          {!statusBesideTitle && statusBadge}
          {actions}
        </div>
      )}
    </div>
  );
};
