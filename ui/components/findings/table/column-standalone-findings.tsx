"use client";

import { ColumnDef } from "@tanstack/react-table";
import { Database } from "lucide-react";

import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { DateWithTime } from "@/components/ui/entities";
import {
  DataTableColumnHeader,
  SeverityBadge,
  StatusFindingBadge,
} from "@/components/ui/table";
import { FindingProps, ProviderType } from "@/types";

import { FindingDetailDrawer } from "./finding-detail-drawer";
import { DeltaValues, NotificationIndicator } from "./notification-indicator";
import { ProviderIconCell } from "./provider-icon-cell";

interface GetStandaloneFindingColumnsOptions {
  includeUpdatedAt?: boolean;
  openFindingId?: string | null;
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
        <div className="max-w-[500px]">
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
        const resourceName = getResourceData(row, "name");

        if (resourceName === "-") {
          return <p className="text-text-neutral-primary text-sm">-</p>;
        }

        return (
          <CodeSnippet
            value={resourceName as string}
            formatter={(value: string) => `...${value.slice(-10)}`}
            icon={<Database size={16} />}
          />
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

        return <ProviderIconCell provider={provider as ProviderType} />;
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
        return (
          <p className="text-text-neutral-primary max-w-[120px] truncate text-sm">
            {regionText}
          </p>
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

  return columns;
}
