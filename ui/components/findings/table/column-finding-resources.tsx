"use client";

import { ColumnDef } from "@tanstack/react-table";
import { CornerDownRight } from "lucide-react";

import { DateWithTime } from "@/components/ui/entities";
import { EntityInfo } from "@/components/ui/entities/entity-info";
import { SeverityBadge } from "@/components/ui/table";
import { FindingResourceRow } from "@/types";

import { NotificationIndicator } from "./notification-indicator";

/**
 * Computes a human-readable "failing for" duration from first_seen_at to now.
 * Returns null if the resource is not failing or has no first_seen_at.
 */
function getFailingForLabel(firstSeenAt: string | null): string | null {
  if (!firstSeenAt) return null;

  const start = new Date(firstSeenAt);
  if (isNaN(start.getTime())) return null;

  const now = new Date();
  const diffMs = now.getTime() - start.getTime();
  if (diffMs < 0) return null;

  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays < 1) return "< 1 day";
  if (diffDays < 30) return `${diffDays} day${diffDays > 1 ? "s" : ""}`;

  const diffMonths = Math.floor(diffDays / 30);
  if (diffMonths < 12)
    return `${diffMonths} month${diffMonths > 1 ? "s" : ""}`;

  const diffYears = Math.floor(diffMonths / 12);
  return `${diffYears} year${diffYears > 1 ? "s" : ""}`;
}

export function getColumnFindingResources(): ColumnDef<FindingResourceRow>[] {
  return [
    // Notification column — muted indicator only
    {
      id: "notification",
      header: () => null,
      cell: ({ row }) => (
        <NotificationIndicator
          isMuted={row.original.isMuted}
          mutedReason={row.original.mutedReason}
        />
      ),
      enableSorting: false,
      enableHiding: false,
    },
    // Child icon — corner-down-right arrow
    {
      id: "childIcon",
      header: () => null,
      cell: () => (
        <div className="flex size-6 items-center justify-center">
          <CornerDownRight className="text-text-neutral-tertiary size-4" />
        </div>
      ),
      enableSorting: false,
      enableHiding: false,
    },
    // Resource — name + uid (EntityInfo with resource icon)
    {
      id: "resource",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Resource
        </span>
      ),
      cell: ({ row }) => (
        <EntityInfo
          entityAlias={row.original.resourceName}
          entityId={row.original.resourceUid}
        />
      ),
      enableSorting: false,
    },
    // Service
    {
      id: "service",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Service
        </span>
      ),
      cell: ({ row }) => (
        <p className="text-text-neutral-primary max-w-[100px] truncate text-sm">
          {row.original.service}
        </p>
      ),
      enableSorting: false,
    },
    // Region
    {
      id: "region",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Region
        </span>
      ),
      cell: ({ row }) => (
        <p className="text-text-neutral-primary max-w-[120px] truncate text-sm">
          {row.original.region}
        </p>
      ),
      enableSorting: false,
    },
    // Severity
    {
      id: "severity",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Severity
        </span>
      ),
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      enableSorting: false,
    },
    // Account — alias + uid (EntityInfo with provider logo)
    {
      id: "account",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Account
        </span>
      ),
      cell: ({ row }) => (
        <EntityInfo
          cloudProvider={row.original.providerType}
          entityAlias={row.original.providerAlias}
          entityId={row.original.providerUid}
        />
      ),
      enableSorting: false,
    },
    // Last seen
    {
      id: "lastSeen",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Last seen
        </span>
      ),
      cell: ({ row }) => (
        <DateWithTime dateTime={row.original.lastSeenAt} />
      ),
      enableSorting: false,
    },
    // Failing for — duration since first_seen_at
    {
      id: "failingFor",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Failing for
        </span>
      ),
      cell: ({ row }) => {
        const label = getFailingForLabel(row.original.firstSeenAt);
        return (
          <p className="text-text-neutral-primary text-sm">
            {label || "-"}
          </p>
        );
      },
      enableSorting: false,
    },
  ];
}
