"use client";

import { ColumnDef } from "@tanstack/react-table";
import { useRouter, useSearchParams } from "next/navigation";

import { InfoIcon } from "@/components/icons";
import { TableLink } from "@/components/ui/custom";
import { DateWithTime, EntityInfo } from "@/components/ui/entities";
import { TriggerSheet } from "@/components/ui/sheet";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { ProviderType, ScanProps } from "@/types";

import { TriggerIcon } from "../../trigger-icon";
import { DataTableDownloadDetails } from "./data-table-download-details";
import { DataTableRowActions } from "./data-table-row-actions";
import { DataTableRowDetails } from "./data-table-row-details";

const getScanData = (row: { original: ScanProps }) => {
  return row.original;
};

const ScanDetailsCell = ({ row }: { row: any }) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scanId = searchParams.get("scanId");
  const isOpen = scanId === row.original.id;
  const scanState = row.original.attributes?.state;
  const isExecuting = scanState === "executing" || scanState === "available";

  const handleOpenChange = (open: boolean) => {
    if (isExecuting) return;

    const params = new URLSearchParams(searchParams.toString());

    if (open) {
      params.set("scanId", row.original.id);
    } else {
      params.delete("scanId");
    }

    router.push(`?${params.toString()}`, { scroll: false });
  };

  return (
    <div className="flex w-9 items-center justify-center">
      <TriggerSheet
        triggerComponent={
          <InfoIcon
            className={
              isExecuting ? "cursor-default text-gray-400" : "text-primary"
            }
            size={16}
          />
        }
        title="Scan Details"
        description="View the scan details"
        open={isOpen}
        onOpenChange={handleOpenChange}
      >
        {isOpen && <DataTableRowDetails entityId={row.original.id} />}
      </TriggerSheet>
    </div>
  );
};

export const ColumnGetScans: ColumnDef<ScanProps>[] = [
  {
    id: "moreInfo",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Details" />
    ),
    cell: ({ row }) => <ScanDetailsCell row={row} />,
    enableSorting: false,
  },
  {
    accessorKey: "cloudProvider",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Cloud Provider" />
    ),
    cell: ({ row }) => {
      const providerInfo = row.original.providerInfo;

      if (!providerInfo) {
        return <span className="font-medium">No provider info</span>;
      }

      const { provider, uid, alias } = providerInfo;

      return (
        <EntityInfo
          cloudProvider={provider as ProviderType}
          entityAlias={alias}
          entityId={uid}
        />
      );
    },
    enableSorting: false,
  },

  {
    accessorKey: "started_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Started at" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { started_at },
      } = getScanData(row);

      return (
        <div className="w-[100px]">
          <DateWithTime dateTime={started_at} />
        </div>
      );
    },
    enableSorting: false,
  },
  {
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { state },
      } = getScanData(row);
      return (
        <div className="flex items-center justify-center">
          <StatusBadge
            status={state}
            loadingProgress={row.original.attributes.progress}
          />
        </div>
      );
    },
    enableSorting: false,
  },
  {
    accessorKey: "findings",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Findings" />
    ),
    cell: ({ row }) => {
      const { id } = getScanData(row);
      const scanState = row.original.attributes?.state;
      return (
        <TableLink
          href={`/findings?filter[scan__in]=${id}&filter[status__in]=FAIL`}
          isDisabled={scanState !== "completed"}
          label="See Findings"
        />
      );
    },
    enableSorting: false,
  },
  {
    accessorKey: "compliance",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Compliance" />
    ),
    cell: ({ row }) => {
      const { id } = getScanData(row);
      const scanState = row.original.attributes?.state;
      return (
        <TableLink
          href={`/compliance?scanId=${id}`}
          isDisabled={!["completed"].includes(scanState)}
          label="See Compliance"
        />
      );
    },
    enableSorting: false,
  },
  {
    id: "download",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Download" />
    ),
    cell: ({ row }) => {
      return (
        <div className="mx-auto w-fit">
          <DataTableDownloadDetails row={row} />
        </div>
      );
    },
    enableSorting: false,
  },
  {
    accessorKey: "resources",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Resources" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { unique_resource_count },
      } = getScanData(row);
      return (
        <div className="flex w-fit items-center justify-center">
          <span className="text-xs font-medium">{unique_resource_count}</span>
        </div>
      );
    },
    enableSorting: false,
  },
  {
    accessorKey: "scheduled_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Scheduled at" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { scheduled_at },
      } = getScanData(row);
      return <DateWithTime dateTime={scheduled_at} />;
    },
    enableSorting: false,
  },
  {
    accessorKey: "completed_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Completed at"}
        param="updated_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { completed_at },
      } = getScanData(row);
      return <DateWithTime dateTime={completed_at} />;
    },
  },
  {
    accessorKey: "trigger",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Trigger"}
        param="trigger"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { trigger },
      } = getScanData(row);
      return (
        <div className="flex w-9 items-center justify-center">
          <TriggerIcon trigger={trigger} iconSize={16} />
        </div>
      );
    },
  },
  {
    accessorKey: "scanName",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Scan name"} param="name" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { name },
      } = getScanData(row);

      if (!name || name.length === 0) {
        return <span className="font-medium">-</span>;
      }
      return (
        <div className="flex w-fit items-center justify-center">
          <span className="text-xs font-medium">
            {name === "Daily scheduled scan" ? "scheduled scan" : name}
          </span>
        </div>
      );
    },
  },
  {
    id: "actions",
    header: ({ column }) => <DataTableColumnHeader column={column} title="" />,
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
    enableSorting: false,
  },
];
