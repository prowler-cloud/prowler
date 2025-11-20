"use client";

import { ColumnDef } from "@tanstack/react-table";
import { Database } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { DataTableRowDetails } from "@/components/findings/table";
import { DataTableRowActions } from "@/components/findings/table/data-table-row-actions";
import { InfoIcon } from "@/components/icons";
import {
  DateWithTime,
  EntityInfoShort,
  SnippetChip,
} from "@/components/ui/entities";
import { TriggerSheet } from "@/components/ui/sheet";
import {
  DataTableColumnHeader,
  SeverityBadge,
  StatusFindingBadge,
} from "@/components/ui/table";
import { FindingProps, ProviderType } from "@/types";

import { Muted } from "../muted";
import { DeltaIndicator } from "./delta-indicator";

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

const FindingDetailsCell = ({ row }: { row: any }) => {
  const searchParams = useSearchParams();
  const findingId = searchParams.get("id");
  const isOpen = findingId === row.original.id;

  const handleOpenChange = (open: boolean) => {
    const params = new URLSearchParams(searchParams);

    if (open) {
      params.set("id", row.original.id);
    } else {
      params.delete("id");
    }

    window.history.pushState({}, "", `?${params.toString()}`);
  };

  return (
    <div className="flex max-w-10 justify-center">
      <TriggerSheet
        triggerComponent={
          <InfoIcon className="text-button-primary" size={16} />
        }
        title="Finding Details"
        description="View the finding details"
        defaultOpen={isOpen}
        onOpenChange={handleOpenChange}
      >
        <DataTableRowDetails
          entityId={row.original.id}
          findingDetails={row.original}
        />
      </TriggerSheet>
    </div>
  );
};

export const ColumnFindings: ColumnDef<FindingProps>[] = [
  {
    id: "moreInfo",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Details" />
    ),
    cell: ({ row }) => <FindingDetailsCell row={row} />,
    enableSorting: false,
  },
  {
    accessorKey: "check",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Finding"}
        param="check_id"
      />
    ),
    cell: ({ row }) => {
      const { checktitle } = getFindingsMetadata(row);
      const {
        attributes: { muted, muted_reason },
      } = getFindingsData(row);
      const { delta } = row.original.attributes;

      return (
        <div className="3xl:max-w-[660px] relative flex max-w-[410px] flex-row items-center gap-2">
          <div className="flex flex-row items-center gap-4">
            {delta === "new" || delta === "changed" ? (
              <DeltaIndicator delta={delta} />
            ) : (
              <div className="w-2" />
            )}
            <p className="mr-7 text-sm break-words whitespace-normal">
              {checktitle}
            </p>
          </div>
          <span className="absolute top-1/2 -right-2 -translate-y-1/2">
            <Muted isMuted={muted} mutedReason={muted_reason || ""} />
          </span>
        </div>
      );
    },
  },
  {
    accessorKey: "resourceName",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Resource name" />
    ),
    cell: ({ row }) => {
      const resourceName = getResourceData(row, "name");

      return (
        <SnippetChip
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
        title={"Severity"}
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
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Status"} param="status" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { status },
      } = getFindingsData(row);

      return <StatusFindingBadge status={status} />;
    },
  },
  {
    accessorKey: "updated_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Last seen"}
        param="updated_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { updated_at },
      } = getFindingsData(row);
      return (
        <div className="w-[100px]">
          <DateWithTime dateTime={updated_at} />
        </div>
      );
    },
  },
  // {
  //   accessorKey: "scanName",
  //   header: "Scan Name",
  //   cell: ({ row }) => {
  //     const name = getScanData(row, "name");

  //     return (
  //       <p className="text-small">
  //         {typeof name === "string" || typeof name === "number"
  //           ? name
  //           : "Invalid data"}
  //       </p>
  //     );
  //   },
  // },
  {
    accessorKey: "region",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Region" />
    ),
    cell: ({ row }) => {
      const region = getResourceData(row, "region");

      return (
        <div className="w-[80px] text-xs">
          {typeof region === "string" ? region : "Invalid region"}
        </div>
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
      return <p className="max-w-96 truncate text-xs">{servicename}</p>;
    },
    enableSorting: false,
  },
  {
    accessorKey: "cloudProvider",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Cloud Provider" />
    ),
    cell: ({ row }) => {
      const provider = getProviderData(row, "provider");
      const alias = getProviderData(row, "alias");
      const uid = getProviderData(row, "uid");

      return (
        <>
          <EntityInfoShort
            cloudProvider={provider as ProviderType}
            entityAlias={alias as string}
            entityId={uid as string}
          />
        </>
      );
    },
    enableSorting: false,
  },
  {
    id: "actions",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Actions" />
    ),
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
    enableSorting: false,
  },
];
