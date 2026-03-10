"use client";

import { ColumnDef, RowSelectionState } from "@tanstack/react-table";
import { Database } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { FindingDetail } from "@/components/findings/table";
import { DataTableRowActions } from "@/components/findings/table";
import { Checkbox } from "@/components/shadcn";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { DateWithTime } from "@/components/ui/entities";
import {
  DataTableColumnHeader,
  SeverityBadge,
  StatusFindingBadge,
} from "@/components/ui/table";
import { FindingProps, ProviderType } from "@/types";

// TODO: PROWLER-379 - Enable ImpactedResourcesCell when backend supports grouped findings
// import { ImpactedResourcesCell } from "./impacted-resources-cell";
import { DeltaValues, NotificationIndicator } from "./notification-indicator";
import { ProviderIconCell } from "./provider-icon-cell";

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
  return (
    row.original.relationships?.resource?.attributes?.[field] ||
    `No ${field} found in resource`
  );
};

const getProviderData = (
  row: { original: FindingProps },
  field: keyof FindingProps["relationships"]["provider"]["attributes"],
) => {
  return (
    row.original.relationships?.provider?.attributes?.[field] ||
    `No ${field} found in provider`
  );
};

// Component for finding title that opens the detail drawer
const FindingTitleCell = ({ row }: { row: { original: FindingProps } }) => {
  const searchParams = useSearchParams();
  const findingId = searchParams.get("id");
  const isOpen = findingId === row.original.id;
  const { checktitle } = row.original.attributes.check_metadata;

  return (
    <FindingDetail
      findingDetails={row.original}
      defaultOpen={isOpen}
      trigger={
        <div className="max-w-[500px]">
          <p className="text-text-neutral-primary hover:text-button-tertiary cursor-pointer text-left text-sm break-words whitespace-normal hover:underline">
            {checktitle}
          </p>
        </div>
      }
    />
  );
};

// Function to generate columns with access to selection state
export function getColumnFindings(
  rowSelection: RowSelectionState,
  selectableRowCount: number,
): ColumnDef<FindingProps>[] {
  // Calculate selection state from rowSelection for header checkbox
  const selectedCount = Object.values(rowSelection).filter(Boolean).length;
  const isAllSelected =
    selectedCount > 0 && selectedCount === selectableRowCount;
  const isSomeSelected =
    selectedCount > 0 && selectedCount < selectableRowCount;

  return [
    // Notification column - shows new/changed/muted indicators
    {
      id: "notification",
      header: () => null,
      cell: ({ row }) => {
        const finding = row.original;
        const isMuted = finding.attributes.muted;
        const mutedReason = finding.attributes.muted_reason;
        const delta = finding.attributes.delta as
          | (typeof DeltaValues)[keyof typeof DeltaValues]
          | undefined;

        return (
          <NotificationIndicator
            delta={delta}
            isMuted={isMuted}
            mutedReason={mutedReason}
          />
        );
      },
      enableSorting: false,
      enableHiding: false,
    },
    // Select column
    {
      id: "select",
      header: ({ table }) => {
        const headerChecked = isAllSelected
          ? true
          : isSomeSelected
            ? "indeterminate"
            : false;

        return (
          <div className="ml-1 flex w-6 items-center justify-center pr-4">
            <Checkbox
              checked={headerChecked}
              onCheckedChange={(checked) =>
                table.toggleAllPageRowsSelected(checked === true)
              }
              aria-label="Select all"
              disabled={selectableRowCount === 0}
            />
          </div>
        );
      },
      cell: ({ row }) => {
        const finding = row.original;
        const isMuted = finding.attributes.muted;
        const isSelected = !!rowSelection[row.id];

        return (
          <div className="ml-1 flex w-6 items-center justify-center pr-4">
            <Checkbox
              checked={isSelected}
              disabled={isMuted}
              onCheckedChange={(checked) =>
                row.toggleSelected(checked === true)
              }
              aria-label="Select row"
            />
          </div>
        );
      },
      enableSorting: false,
      enableHiding: false,
    },
    // Status column
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
    // Finding column - clickable to open detail sheet
    {
      accessorKey: "check",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Finding"
          param="check_id"
        />
      ),
      cell: ({ row }) => <FindingTitleCell row={row} />,
    },
    // Resource name column
    {
      accessorKey: "resourceName",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Resource name" />
      ),
      cell: ({ row }) => {
        const resourceName = getResourceData(row, "name");

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
    // Severity column
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
    // Provider column
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
    // Service column
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
    // Region column
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
    // TODO: PROWLER-379 - Enable Impacted Resources column when backend supports grouped findings
    // {
    //   accessorKey: "impactedResources",
    //   header: ({ column }) => (
    //     <DataTableColumnHeader column={column} title="Impacted Resources" />
    //   ),
    //   cell: () => {
    //     return <ImpactedResourcesCell impacted={1} total={1} />;
    //   },
    //   enableSorting: false,
    // },
    // Time column
    {
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
    },
    // Actions column - dropdown with Mute/Jira options
    {
      id: "actions",
      header: () => <div className="w-10" />,
      cell: ({ row }) => <DataTableRowActions row={row} />,
      enableSorting: false,
    },
  ];
}
