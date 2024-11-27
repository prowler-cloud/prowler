"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DataTableColumnHeader, SeverityBadge } from "@/components/ui/table";
import { FindingProps } from "@/types";

const getFindingsData = (row: { original: FindingProps }) => {
  return row.original;
};

const getFindingsMetadata = (row: { original: FindingProps }) => {
  return row.original.attributes.check_metadata;
};

export const ColumnNewFindingsToDate: ColumnDef<FindingProps>[] = [
  {
    accessorKey: "check",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Check"} param="check_id" />
    ),
    cell: ({ row }) => {
      const { checktitle } = getFindingsMetadata(row);
      return <p className="max-w-80 truncate text-small">{checktitle}</p>;
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
];
