"use client";

import { ColumnDef } from "@tanstack/react-table";
import { Container } from "lucide-react";

import { DateWithTime, EntityInfo } from "@/components/shadcn/entities";
import {
  DataTableColumnHeader,
  SeverityBadge,
  StatusFindingBadge,
} from "@/components/shadcn/table";
import { getRegionFlag } from "@/lib/region-flags";
import { getOptionalText } from "@/lib/utils";
import { FindingProps, ProviderType } from "@/types";
import type {
  FindingTriageLoadedNote,
  FindingTriageSummary,
} from "@/types/findings-triage";

import { DataTableRowActions } from "./data-table-row-actions";
import { FindingDetailDrawer } from "./finding-detail-drawer";
import { FindingTriageStatusCell } from "./finding-triage-cells";
import type { FindingTriageUpdateHandler } from "./finding-triage-status-control";
import { DeltaValues, NotificationIndicator } from "./notification-indicator";
import { ProviderIconCell } from "./provider-icon-cell";

interface GetStandaloneFindingColumnsOptions {
  includeUpdatedAt?: boolean;
  openFindingId?: string | null;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageNoteLoadAction?: (
    triage: FindingTriageSummary,
  ) => Promise<FindingTriageLoadedNote>;
}

const getFindingsData = (row: { original: FindingProps }) => {
  return row.original;
};

const getFindingsMetadata = (row: { original: FindingProps }) => {
  return row.original.attributes.check_metadata;
};

const getResourceData = (
  row: { original: FindingProps },
  field: keyof FindingProps["relationships"]["resource"]["attributes"],
) => {
  return row.original.relationships?.resource?.attributes?.[field] || "-";
};

const getProviderData = (
  row: { original: FindingProps },
  field: keyof FindingProps["relationships"]["provider"]["attributes"],
) => {
  return row.original.relationships?.provider?.attributes?.[field] || "-";
};

function FindingTitleCell({
  finding,
  defaultOpen = false,
}: {
  finding: FindingProps;
  defaultOpen?: boolean;
}) {
  return (
    <FindingDetailDrawer
      finding={finding}
      defaultOpen={defaultOpen}
      trigger={
        <div className="max-w-[500px] min-w-[160px]">
          <p className="text-text-neutral-primary hover:text-button-tertiary cursor-pointer text-left text-sm break-words whitespace-normal hover:underline">
            {finding.attributes.check_metadata.checktitle}
          </p>
        </div>
      }
    />
  );
}

export function getStandaloneFindingColumns({
  includeUpdatedAt = false,
  openFindingId = null,
  onTriageUpdateAction,
  onTriageNoteLoadAction,
}: GetStandaloneFindingColumnsOptions = {}): ColumnDef<FindingProps>[] {
  const columns: ColumnDef<FindingProps>[] = [
    {
      id: "notification",
      header: () => null,
      cell: ({ row }) => {
        const finding = row.original;
        const delta = finding.attributes.delta as
          | (typeof DeltaValues)[keyof typeof DeltaValues]
          | undefined;

        return (
          <NotificationIndicator
            delta={delta}
            isMuted={finding.attributes.muted}
            mutedReason={finding.attributes.muted_reason}
            showDeltaWhenMuted
            reserveMutedSlot
          />
        );
      },
      enableSorting: false,
      enableHiding: false,
    },
    {
      accessorKey: "status",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Status" param="status" />
      ),
      cell: ({ row }) => {
        const {
          attributes: { status },
        } = getFindingsData(row);

        return <StatusFindingBadge status={status} />;
      },
    },
    {
      accessorKey: "check",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Finding"
          param="check_id"
        />
      ),
      cell: ({ row }) => (
        <FindingTitleCell
          finding={row.original}
          defaultOpen={openFindingId === row.original.id}
        />
      ),
    },
    {
      accessorKey: "resourceName",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Resource name" />
      ),
      cell: ({ row }) => {
        const name = getResourceData(row, "name");
        const uid = getResourceData(row, "uid");
        const entityAlias = getOptionalText(name);
        const entityId = getOptionalText(uid);

        return (
          <div className="max-w-[240px]">
            <EntityInfo
              nameIcon={<Container className="size-4" />}
              entityAlias={entityAlias}
              entityId={entityId}
            />
          </div>
        );
      },
      enableSorting: false,
    },
    {
      accessorKey: "severity",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Severity"
          param="severity"
        />
      ),
      cell: ({ row }) => {
        const {
          attributes: { severity },
        } = getFindingsData(row);
        return <SeverityBadge severity={severity} />;
      },
    },
    {
      accessorKey: "provider",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Provider" />
      ),
      cell: ({ row }) => {
        const provider = getProviderData(row, "provider");

        return (
          <ProviderIconCell
            provider={provider as ProviderType}
            className="size-8"
          />
        );
      },
      enableSorting: false,
    },
    {
      accessorKey: "service",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Service" />
      ),
      cell: ({ row }) => {
        const { servicename } = getFindingsMetadata(row);
        return (
          <p className="text-text-neutral-primary max-w-[100px] truncate text-sm">
            {servicename}
          </p>
        );
      },
      enableSorting: false,
    },
    {
      accessorKey: "region",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Region" />
      ),
      cell: ({ row }) => {
        const region = getResourceData(row, "region");
        const regionText = typeof region === "string" ? region : "-";
        const regionFlag =
          typeof region === "string" ? getRegionFlag(region) : "";
        return (
          <span className="text-text-neutral-primary flex max-w-[140px] min-w-0 items-center gap-1.5 truncate text-sm whitespace-nowrap">
            {regionFlag && (
              <span className="translate-y-px text-base leading-none">
                {regionFlag}
              </span>
            )}
            <span className="truncate">{regionText}</span>
          </span>
        );
      },
      enableSorting: false,
    },
  ];

  if (includeUpdatedAt) {
    columns.push({
      accessorKey: "updated_at",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Time"
          param="updated_at"
        />
      ),
      cell: ({ row }) => {
        const {
          attributes: { updated_at },
        } = getFindingsData(row);
        return <DateWithTime dateTime={updated_at} />;
      },
    });
  }

  columns.push(
    {
      id: "triage",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Triage" />
      ),
      cell: ({ row }) => (
        <FindingTriageStatusCell
          triage={row.original.triage}
          onTriageUpdateAction={onTriageUpdateAction}
        />
      ),
      enableSorting: false,
    },
    {
      id: "actions",
      size: 56,
      header: () => <div className="w-10" />,
      cell: ({ row }) => {
        const resourceName = getResourceData(row, "name");
        const providerAlias = getProviderData(row, "alias");
        const providerType = getProviderData(row, "provider");

        return (
          <DataTableRowActions
            row={row}
            findingContext={{
              title: row.original.attributes.check_metadata.checktitle,
              resource: getOptionalText(resourceName),
              provider: getOptionalText(providerAlias),
              providerType: getOptionalText(providerType) as
                | ProviderType
                | undefined,
            }}
            onTriageUpdateAction={onTriageUpdateAction}
            onTriageNoteLoadAction={onTriageNoteLoadAction}
          />
        );
      },
      enableSorting: false,
    },
  );

  return columns;
}
