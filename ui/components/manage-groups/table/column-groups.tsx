"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { ProviderGroup } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

const getProviderData = (row: { original: ProviderGroup }) => {
  return row.original;
};

export const ColumnGroups: ColumnDef<ProviderGroup>[] = [
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Name"} param="name" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { name },
      } = getProviderData(row);
      return <p className="text-small">{name}</p>;
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
      } = getProviderData(row);
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
