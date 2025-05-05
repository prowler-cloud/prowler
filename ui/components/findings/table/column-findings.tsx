"use client";

import { ColumnDef } from "@tanstack/react-table";
import { useSearchParams } from "next/navigation";

import { DataTableRowDetails } from "@/components/findings/table";
import { InfoIcon } from "@/components/icons";
import { DateWithTime, EntityInfoShort } from "@/components/ui/entities";
import { TriggerSheet } from "@/components/ui/sheet";
import {
  DataTableColumnHeader,
  SeverityBadge,
  StatusFindingBadge,
} from "@/components/ui/table";
import { FindingProps } from "@/types";

import { Muted } from "../muted";

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

// const getScanData = (
//   row: { original: FindingProps },
//   field: keyof FindingProps["relationships"]["scan"]["attributes"],
// ) => {
//   return (
//     row.original.relationships?.scan?.attributes?.[field] ||
//     `No ${field} found in scan`
//   );
// };

const FindingDetailsCell = ({ row }: { row: any }) => {
  const searchParams = useSearchParams();
  const findingId = searchParams.get("id");
  const isOpen = findingId === row.original.id;

  return (
    <div className="flex justify-center">
      <TriggerSheet
        triggerComponent={<InfoIcon className="text-primary" size={16} />}
        title="Finding Details"
        description="View the finding details"
        defaultOpen={isOpen}
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
    header: "Details",
    cell: ({ row }) => <FindingDetailsCell row={row} />,
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
        attributes: { muted },
      } = getFindingsData(row);
      return (
        <div className="relative flex max-w-[410px] flex-row items-center gap-2 3xl:max-w-[660px]">
          <p className="mr-7 whitespace-normal break-words text-sm">
            {checktitle}
          </p>
          <span className="absolute -right-2 top-1/2 -translate-y-1/2">
            <Muted isMuted={muted} />
          </span>
        </div>
      );
    },
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
    header: "Region",
    cell: ({ row }) => {
      const region = getResourceData(row, "region");

      return (
        <div className="w-[80px] text-xs">
          {typeof region === "string" ? region : "Invalid region"}
        </div>
      );
    },
  },
  {
    accessorKey: "service",
    header: "Service",
    cell: ({ row }) => {
      const { servicename } = getFindingsMetadata(row);
      return <p className="max-w-96 truncate text-xs">{servicename}</p>;
    },
  },
  {
    accessorKey: "cloudProvider",
    header: "Cloud provider",
    cell: ({ row }) => {
      const provider = getProviderData(row, "provider");
      const alias = getProviderData(row, "alias");
      const uid = getProviderData(row, "uid");

      return (
        <>
          <EntityInfoShort
            cloudProvider={provider as "aws" | "azure" | "gcp" | "kubernetes"}
            entityAlias={alias as string}
            entityId={uid as string}
          />
        </>
      );
    },
  },
];
