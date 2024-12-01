"use client";

import { ColumnDef } from "@tanstack/react-table";
import { useSearchParams } from "next/navigation";

import { InfoIcon } from "@/components/icons";
import { DateWithTime, EntityInfoShort } from "@/components/ui/entities";
import { TriggerSheet } from "@/components/ui/sheet";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { ScanProps } from "@/types";

import { LinkToFindingsFromScan } from "../../link-to-findings-from-scan";
import { DataTableRowActions } from "./data-table-row-actions";
import { DataTableRowDetails } from "./data-table-row-details";

const getScanData = (row: { original: ScanProps }) => {
  return row.original;
};

export const ColumnGetScans: ColumnDef<ScanProps>[] = [
  {
    id: "moreInfo",
    header: "Details",
    cell: ({ row }) => {
      const searchParams = useSearchParams();
      const scanId = searchParams.get("scanId");
      const isOpen = scanId === row.original.id;

      return (
        <div className="flex w-9 items-center justify-center">
          <TriggerSheet
            triggerComponent={<InfoIcon className="text-primary" size={16} />}
            title="Scan Details"
            description="View the scan details"
            defaultOpen={isOpen}
          >
            <DataTableRowDetails entityId={row.original.id} />
          </TriggerSheet>
        </div>
      );
    },
  },
  {
    accessorKey: "cloudProvider",
    header: () => <p className="pr-8">Cloud provider</p>,
    cell: ({ row }) => {
      const providerInfo = row.original.providerInfo;

      if (!providerInfo) {
        return <span className="font-medium">No provider info</span>;
      }

      const { provider, uid, alias } = providerInfo;

      return (
        <EntityInfoShort
          cloudProvider={provider as "aws" | "azure" | "gcp" | "kubernetes"}
          entityAlias={alias}
          entityId={uid}
        />
      );
    },
  },

  {
    accessorKey: "started_at",
    header: () => <p className="pr-8">Started at</p>,
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
  },
  {
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Status"} param="state" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { state },
      } = getScanData(row);
      return (
        <StatusBadge
          status={state}
          loadingProgress={row.original.attributes.progress}
        />
      );
    },
  },
  {
    accessorKey: "findings",
    header: "Findings",
    cell: ({ row }) => {
      const { id } = getScanData(row);
      return <LinkToFindingsFromScan scanId={id} />;
    },
  },
  // {
  //   accessorKey: "scanner_args",
  //   header: "Scanner Args",
  //   cell: ({ row }) => {
  //     const {
  //       attributes: { scanner_args },
  //     } = getScanData(row);
  //     return <p className="font-medium">{scanner_args?.only_logs}</p>;
  //   },
  // },
  {
    accessorKey: "resources",
    header: "Resources",
    cell: ({ row }) => {
      const {
        attributes: { unique_resource_count },
      } = getScanData(row);
      return <p className="font-medium">{unique_resource_count}</p>;
    },
  },
  {
    accessorKey: "next_scan_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Next execution"}
        param="next_scan_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { next_scan_at },
      } = getScanData(row);
      return <DateWithTime dateTime={next_scan_at} />;
    },
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
      <DataTableColumnHeader column={column} title={"Type"} param="trigger" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { trigger },
      } = getScanData(row);
      return <p className="text-tiny font-medium uppercase">{trigger}</p>;
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

      return <span className="text-xs font-medium">{name}</span>;
    },
  },
  {
    id: "actions",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
