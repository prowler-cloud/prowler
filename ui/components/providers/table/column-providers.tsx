"use client";

import { ColumnDef, Row, RowSelectionState } from "@tanstack/react-table";
import { Building2, FolderTree } from "lucide-react";

import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import { Badge } from "@/components/shadcn";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import { DateWithTime, EntityInfo } from "@/components/shadcn/entities";
import { DataTableColumnHeader } from "@/components/shadcn/table";
import { DataTableExpandAllToggle } from "@/components/shadcn/table/data-table-expand-all-toggle";
import { DataTableExpandableCell } from "@/components/shadcn/table/data-table-expandable-cell";
import {
  isProvidersOrganizationRow,
  PROVIDERS_GROUP_KIND,
  ProvidersProviderRow,
  ProvidersTableRow,
} from "@/types/providers-table";
import {
  SCAN_CONFIGURATION_LIST_STATUS,
  ScanConfigurationData,
  type ScanConfigurationListStatus,
} from "@/types/scan-configurations";
import type {
  ScanScheduleCapability,
  ScanScheduleProvider,
} from "@/types/schedules";

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
      <Badge variant="success" className="text-sm">
        Connected
      </Badge>
    );
  }

  if (connected === false) {
    return (
      <Badge variant="error" className="text-sm">
        Connection failed
      </Badge>
    );
  }

  return (
    <Badge variant="tag" className="text-text-neutral-secondary text-sm">
      Not connected
    </Badge>
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
  selectedScheduleProviderIds: string[],
  selectedScheduleProviders: ScanScheduleProvider[],
  onClearSelection: () => void,
  onOpenProviderWizard: (initialData?: ProviderWizardInitialData) => void,
  onOpenOrganizationWizard: (initialData: OrgWizardInitialData) => void,
  scanScheduleCapability?: ScanScheduleCapability,
  scanConfigs: ScanConfigurationData[] = [],
  scanConfigStatus: ScanConfigurationListStatus = SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE,
  scanConfigIdByProviderId: ReadonlyMap<string, string> = new Map(),
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

        const provider = row.original as ProvidersProviderRow;
        const lastScanAt =
          provider.lastScanAt !== undefined
            ? provider.lastScanAt
            : provider.attributes.connection.last_checked_at;

        if (!lastScanAt) {
          return (
            <span className="text-text-neutral-tertiary text-sm">Never</span>
          );
        }

        return <DateWithTime dateTime={lastScanAt} showTime />;
      },
      enableSorting: false,
    },
    {
      id: "scanSchedule",
      size: 180,
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

        return <LinkToScans schedule={row.original.scheduleSummary} />;
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
        const currentScanConfigId = isProvidersOrganizationRow(row.original)
          ? null
          : (scanConfigIdByProviderId.get(row.original.id) ?? null);

        return (
          <DataTableRowActions
            row={row}
            hasSelection={hasSelection}
            isRowSelected={row.getIsSelected()}
            testableProviderIds={testableProviderIds}
            selectedScheduleProviderIds={selectedScheduleProviderIds}
            selectedScheduleProviders={selectedScheduleProviders}
            onClearSelection={onClearSelection}
            onOpenProviderWizard={onOpenProviderWizard}
            onOpenOrganizationWizard={onOpenOrganizationWizard}
            scanConfigs={scanConfigs}
            scanConfigStatus={scanConfigStatus}
            currentScanConfigId={currentScanConfigId}
            capability={scanScheduleCapability}
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
