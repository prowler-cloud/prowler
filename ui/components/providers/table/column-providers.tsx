"use client";

import { ColumnDef } from "@tanstack/react-table";
import { Building2, FolderTree, ShieldCheck, ShieldOff } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { DataTableExpandAllToggle } from "@/components/ui/table/data-table-expand-all-toggle";
import { DataTableExpandableCell } from "@/components/ui/table/data-table-expandable-cell";
import {
  isProvidersOrganizationRow,
  PROVIDERS_GROUP_KIND,
  ProvidersOrganizationRow,
  ProvidersProviderRow,
  ProvidersTableRow,
} from "@/types/providers-table";

import { LinkToScans } from "../link-to-scans";
import { ProviderInfo } from "../provider-info";
import { DataTableRowActions } from "./data-table-row-actions";

interface GroupNameChipsProps {
  groupNames?: string[];
}

const OrganizationCell = ({
  organization,
}: {
  organization: ProvidersOrganizationRow;
}) => {
  const Icon =
    organization.groupKind === PROVIDERS_GROUP_KIND.ORGANIZATION
      ? Building2
      : FolderTree;

  return (
    <div className="flex min-w-0 items-center gap-3">
      <div className="bg-bg-neutral-tertiary text-text-neutral-primary flex size-9 shrink-0 items-center justify-center rounded-xl">
        <Icon className="size-4" />
      </div>
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="truncate font-medium">{organization.name}</span>
        {organization.externalId && (
          <span className="text-text-neutral-tertiary truncate text-xs">
            UID: {organization.externalId}
          </span>
        )}
      </div>
    </div>
  );
};

const ProviderStatusCell = ({ connected }: { connected: boolean | null }) => {
  if (connected) {
    return (
      <div className="text-system-success flex items-center gap-2 text-sm">
        <ShieldCheck className="size-4" />
        <span>Connected</span>
      </div>
    );
  }

  return (
    <div className="text-text-neutral-secondary flex items-center gap-2 text-sm">
      <ShieldOff className="size-4" />
      <span>Not connected</span>
    </div>
  );
};

export const ColumnProviders: ColumnDef<ProvidersTableRow>[] = [
  {
    id: "account",
    size: 420,
    accessorFn: (row) =>
      isProvidersOrganizationRow(row) ? row.name : row.attributes.alias,
    header: ({ column, table }) => (
      <div className="flex items-center gap-2">
        <DataTableExpandAllToggle table={table} />
        <DataTableColumnHeader column={column} title="Account" param="alias" />
      </div>
    ),
    cell: ({ row }) => {
      const isExpanded = row.getIsExpanded();

      if (isProvidersOrganizationRow(row.original)) {
        return (
          <DataTableExpandableCell row={row} isExpanded={isExpanded}>
            <OrganizationCell organization={row.original} />
          </DataTableExpandableCell>
        );
      }

      const provider = row.original;

      return (
        <DataTableExpandableCell row={row} isExpanded={isExpanded}>
          <ProviderInfo
            connected={provider.attributes.connection.connected}
            provider={provider.attributes.provider}
            providerAlias={provider.attributes.alias}
            providerUID={provider.attributes.uid}
          />
        </DataTableExpandableCell>
      );
    },
  },
  {
    accessorKey: "groupNames",
    size: 160,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Account Groups" />
    ),
    cell: ({ row }) => {
      if (isProvidersOrganizationRow(row.original)) {
        return (
          <span className="text-text-neutral-tertiary text-sm">
            {row.original.groupKind === PROVIDERS_GROUP_KIND.ORGANIZATION
              ? "Organization"
              : "Organizational Unit"}
          </span>
        );
      }

      return <GroupNameChips groupNames={row.original.groupNames || []} />;
    },
    enableSorting: false,
  },
  {
    id: "lastScan",
    size: 160,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Last Scan" />
    ),
    cell: ({ row }) => {
      if (isProvidersOrganizationRow(row.original)) {
        return <span className="text-text-neutral-tertiary text-sm">-</span>;
      }

      const lastCheckedAt = (row.original as ProvidersProviderRow).attributes
        .connection.last_checked_at;

      if (!lastCheckedAt) {
        return (
          <span className="text-text-neutral-tertiary text-sm">Never</span>
        );
      }

      return <DateWithTime dateTime={lastCheckedAt} showTime />;
    },
    enableSorting: false,
  },
  {
    id: "scanSchedule",
    size: 140,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Scan Schedule" />
    ),
    cell: ({ row }) => {
      if (isProvidersOrganizationRow(row.original)) {
        return (
          <span className="text-text-neutral-tertiary text-sm">
            {row.original.providerCount} Accounts
          </span>
        );
      }

      return <LinkToScans providerUid={row.original.attributes.uid} />;
    },
    enableSorting: false,
  },
  {
    id: "status",
    size: 140,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" param="connected" />
    ),
    cell: ({ row }) => {
      if (isProvidersOrganizationRow(row.original)) {
        return <span className="text-text-neutral-tertiary text-sm">-</span>;
      }

      return (
        <ProviderStatusCell
          connected={row.original.attributes.connection.connected}
        />
      );
    },
  },
  {
    accessorKey: "added",
    size: 140,
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Added"
        param="inserted_at"
      />
    ),
    cell: ({ row }) => {
      if (isProvidersOrganizationRow(row.original)) {
        return <span className="text-text-neutral-tertiary text-sm">-</span>;
      }

      return (
        <DateWithTime
          dateTime={row.original.attributes.inserted_at}
          showTime={false}
        />
      );
    },
  },
  {
    id: "actions",
    size: 56,
    header: ({ column }) => <DataTableColumnHeader column={column} title="" />,
    cell: ({ row }) => <DataTableRowActions row={row} />,
    enableSorting: false,
  },
];

export function GroupNameChips({ groupNames }: GroupNameChipsProps) {
  if (!groupNames || groupNames.length === 0) {
    return (
      <span className="text-text-neutral-tertiary text-sm">No groups</span>
    );
  }

  return (
    <div className="flex max-w-[260px] flex-wrap gap-1">
      {groupNames.map((name) => (
        <Badge key={name} variant="tag">
          {name}
        </Badge>
      ))}
    </div>
  );
}
