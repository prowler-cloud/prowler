"use client";

import { Tooltip } from "@nextui-org/react";
import { ColumnDef } from "@tanstack/react-table";
import { useSearchParams } from "next/navigation";

import { InfoIcon } from "@/components/icons";
import { DownloadIconButton, toast } from "@/components/ui";
import { DateWithTime, EntityInfoShort } from "@/components/ui/entities";
import { TriggerSheet } from "@/components/ui/sheet";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { downloadScanZip } from "@/lib/helper";
import { ProviderType, ScanProps } from "@/types";

import { LinkToFindingsFromScan } from "../../link-to-findings-from-scan";
import { TriggerIcon } from "../../trigger-icon";
import { DataTableRowActions } from "./data-table-row-actions";
import { DataTableRowDetails } from "./data-table-row-details";

const getScanData = (row: { original: ScanProps }) => {
  return row.original;
};

const ScanDetailsCell = ({ row }: { row: any }) => {
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
};

export const ColumnGetScans: ColumnDef<ScanProps>[] = [
  {
    id: "moreInfo",
    header: "Details",
    cell: ({ row }) => <ScanDetailsCell row={row} />,
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
          cloudProvider={provider as ProviderType}
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
    header: "Status",
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
  },
  {
    accessorKey: "findings",
    header: "Findings",
    cell: ({ row }) => {
      const { id } = getScanData(row);
      const scanState = row.original.attributes?.state;
      return (
        <LinkToFindingsFromScan
          scanId={id}
          isDisabled={!["completed", "executing"].includes(scanState)}
        />
      );
    },
  },
  {
    id: "download",
    header: () => (
      <div className="flex items-end gap-x-1">
        <p className="w-fit text-xs">Download</p>
        <Tooltip
          className="text-xs"
          content="Download a ZIP file containing the JSON (OCSF), CSV, and HTML reports."
        >
          <div className="flex items-center gap-2">
            <InfoIcon className="mb-1 text-primary" size={12} />
          </div>
        </Tooltip>
      </div>
    ),
    cell: ({ row }) => {
      const scanId = row.original.id;
      const scanState = row.original.attributes?.state;

      return (
        <DownloadIconButton
          paramId={scanId}
          onDownload={() => downloadScanZip(scanId, toast)}
          isDisabled={scanState !== "completed"}
        />
      );
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
      return (
        <div className="flex w-fit items-center justify-center">
          <span className="text-xs font-medium">{unique_resource_count}</span>
        </div>
      );
    },
  },
  {
    accessorKey: "scheduled_at",
    header: "Scheduled at",
    cell: ({ row }) => {
      const {
        attributes: { scheduled_at },
      } = getScanData(row);
      return <DateWithTime dateTime={scheduled_at} />;
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
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
