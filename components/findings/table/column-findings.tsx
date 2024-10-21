"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { FindingProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

const getFindingsData = (row: { original: FindingProps }) => {
  console.log(row.original);
  return row.original;
};

const getFindingsMetadata = (row: { original: FindingProps }) => {
  return row.original.attributes.check_metadata;
};

export const ColumnFindings: ColumnDef<FindingProps>[] = [
  // {
  //   header: " ",
  //   cell: ({ row }) => <p className="text-medium">{row.index + 1}</p>,
  // },
  {
    accessorKey: "check",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Check"} param="check" />
    ),
    cell: ({ row }) => {
      const { checktitle } = getFindingsMetadata(row);
      return <p className="max-w-96 truncate text-medium">{checktitle}</p>;
    },
  },
  // {
  //   accessorKey: "uid",
  //   header: ({ column }) => (
  //     <DataTableColumnHeader column={column} title={"Id"} param="uid" />
  //   ),
  //   cell: ({ row }) => {
  //     const {
  //       attributes: { uid },
  //     } = getFindingsData(row);
  //     return <SnippetId className="h-7 max-w-48" entityId={uid} />;
  //   },
  // },
  // {
  //   accessorKey: "severity",
  //   header: ({ column }) => (
  //     <DataTableColumnHeader
  //       column={column}
  //       title={"Severity"}
  //       param="severity"
  //     />
  //   ),
  //   cell: ({ row }) => {
  //     const {
  //       attributes: { severity },
  //     } = getFindingsData(row);
  //     return <StatusBadge status={severity} />;
  //   },
  // },
  {
    accessorKey: "status",
    header: "Scan Status",
    cell: () => {
      // Temporarily overwriting the value until the API is functional.
      return <StatusBadge status={"completed"} />;
    },
  },
  {
    accessorKey: "service",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Service"}
        param="service"
      />
    ),
    cell: ({ row }) => {
      const { servicename } = getFindingsMetadata(row);
      return <p className="max-w-96 truncate text-medium">{servicename}</p>;
    },
  },
  {
    accessorKey: "added",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Added"}
        param="inserted_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { inserted_at },
      } = getFindingsData(row);
      return <DateWithTime dateTime={inserted_at} showTime={false} />;
    },
  },
  {
    id: "actions",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
