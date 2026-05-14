"use client";

import { ColumnDef, Row, RowSelectionState } from "@tanstack/react-table";
import {
  Building2,
  FolderTree,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";

import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { DateWithTime, EntityInfo } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { DataTableExpandAllToggle } from "@/components/ui/table/data-table-expand-all-toggle";
import { DataTableExpandableCell } from "@/components/ui/table/data-table-expandable-cell";
import {
  isProvidersOrganizationRow,
  PROVIDERS_GROUP_KIND,
  ProvidersProviderRow,
  ProvidersTableRow,
} from "@/types/providers-table";

import { LinkToScans } from "../link-to-scans";
import { DataTableRowActions } from "./data-table-row-actions";

interface GroupNameChipsProps {
  groupNames?: string[];
}

const OrganizationIcon = ({ groupKind }: { groupKind: string }) => {
  const Icon =
    groupKind === PROVIDERS_GROUP_KIND.ORGANIZATION ? Building2 : FolderTree;

  return (
    <div className="bg-bg-neutral-tertiary text-text-neutral-primary flex size-9 items-center justify-center rounded-xl">
      <Icon className="size-4" />
    </div>
  );
};

const ProviderStatusCell = ({ connected }: { connected: boolean | null }) => {
  if (connected === true) {
    return (
      <div className="text-system-success flex items-center gap-2 text-sm whitespace-nowrap">
        <ShieldCheck className="size-4 shrink-0" />
        <span>Connected</span>
      </div>
    );
  }

  if (connected === false) {
    return (
      <div className="text-text-error-primary flex items-center gap-2 text-sm whitespace-nowrap">
        <ShieldAlert className="size-4 shrink-0" />
        <span>Connection failed</span>
      </div>
    );
  }

  return (
    <div className="text-text-neutral-secondary flex items-center gap-2 text-sm whitespace-nowrap">
      <ShieldOff className="size-4 shrink-0" />
      <span>Not connected</span>
    </div>
  );
};

function getSelectionLabel(row: Row<ProvidersTableRow>): string | undefined {
  const isSelected = row.getIsSelected();
  const isSomeSelected = row.getIsSomeSelected();

  if (!isSelected && !isSomeSelected) return undefined;

  const subRows = row.subRows ?? [];
  const totalLeaves = countLeaves(subRows);
  const selectedLeaves = countSelectedLeaves(subRows);

  return `${selectedLeaves.toLocaleString()} of ${totalLeaves.toLocaleString()} Selected`;
}

function countLeaves(rows: Row<ProvidersTableRow>[]): number {
  let count = 0;
  for (const row of rows) {
    if (row.subRows && row.subRows.length > 0) {
      count += countLeaves(row.subRows);
    } else {
      count++;
    }
  }
  return count;
}

function countSelectedLeaves(rows: Row<ProvidersTableRow>[]): number {
  let count = 0;
  for (const row of rows) {
    if (row.subRows && row.subRows.length > 0) {
      count += countSelectedLeaves(row.subRows);
    } else if (row.getIsSelected()) {
      count++;
    }
  }
  return count;
}

export function getColumnProviders(
  rowSelection: RowSelectionState,
  testableProviderIds: string[],
  onClearSelection: () => void,
  onOpenProviderWizard: (initialData?: ProviderWizardInitialData) => void,
  onOpenOrganizationWizard: (initialData: OrgWizardInitialData) => void,
): ColumnDef<ProvidersTableRow>[] {
  return [
    {
      id: "account",
      size: 420,
      accessorFn: (row) =>
        isProvidersOrganizationRow(row) ? row.name : row.attributes.alias,
      header: ({ column, table }) => (
        <div className="flex items-center gap-2">
          <DataTableExpandAllToggle table={table} />
          <Checkbox
            size="sm"
            checked={table.getIsAllPageRowsSelected()}
            indeterminate={
              !table.getIsAllPageRowsSelected() &&
              table.getIsSomePageRowsSelected()
            }
            onCheckedChange={(checked) =>
              table.toggleAllPageRowsSelected(checked === true)
            }
            onClick={(e) => e.stopPropagation()}
            aria-label="Select all"
          />
          <div className="ml-2">
            <DataTableColumnHeader
              column={column}
              title="Provider"
              param="alias"
            />
          </div>
        </div>
      ),
      cell: ({ row }) => {
        const isExpanded = row.getIsExpanded();

        const checkboxSlot = (
          <Checkbox
            size="sm"
            checked={row.getIsSelected()}
            indeterminate={!row.getIsSelected() && row.getIsSomeSelected()}
            onCheckedChange={(checked) => row.toggleSelected(checked === true)}
            onClick={(e) => e.stopPropagation()}
            aria-label="Select row"
          />
        );

        if (isProvidersOrganizationRow(row.original)) {
          return (
            <DataTableExpandableCell
              row={row}
              isExpanded={isExpanded}
              hideChildIcon
              checkboxSlot={checkboxSlot}
            >
              <EntityInfo
                icon={<OrganizationIcon groupKind={row.original.groupKind} />}
                entityAlias={row.original.name}
                entityId={row.original.externalId ?? undefined}
                badge={getSelectionLabel(row)}
                showCopyAction
              />
            </DataTableExpandableCell>
          );
        }

        const provider = row.original;

        return (
          <DataTableExpandableCell
            row={row}
            isExpanded={isExpanded}
            checkboxSlot={checkboxSlot}
          >
            <EntityInfo
              cloudProvider={provider.attributes.provider}
              entityAlias={provider.attributes.alias}
              entityId={provider.attributes.uid}
            />
          </DataTableExpandableCell>
        );
      },
    },
    {
      accessorKey: "groupNames",
      size: 160,
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Provider Groups" />
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
              {row.original.providerCount} Providers
            </span>
          );
        }

        return (
          <LinkToScans
            hasSchedule={row.original.hasSchedule}
            providerUid={row.original.attributes.uid}
          />
        );
      },
      enableSorting: false,
    },
    {
      id: "status",
      size: 170,
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Status"
          param="connected"
        />
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
            showTime
          />
        );
      },
    },
    {
      id: "actions",
      size: 56,
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="" />
      ),
      cell: ({ row }) => {
        const hasSelection = Object.values(rowSelection).some(Boolean);

        return (
          <DataTableRowActions
            row={row}
            hasSelection={hasSelection}
            isRowSelected={row.getIsSelected()}
            testableProviderIds={testableProviderIds}
            onClearSelection={onClearSelection}
            onOpenProviderWizard={onOpenProviderWizard}
            onOpenOrganizationWizard={onOpenOrganizationWizard}
          />
        );
      },
      enableSorting: false,
    },
  ];
}

export function GroupNameChips({ groupNames }: GroupNameChipsProps) {
  if (!groupNames || groupNames.length === 0) {
    return (
      <span className="text-text-neutral-tertiary text-sm">No groups</span>
    );
  }

  return (
    <div className="flex max-w-[260px] flex-wrap gap-1">
      {groupNames.map((name, index) => (
        <CodeSnippet key={index} value={name} />
      ))}
    </div>
  );
}
