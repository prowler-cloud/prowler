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
      return (
        <p className="text-small font-medium">
          {name.charAt(0).toUpperCase() + name.slice(1).toLowerCase()}
        </p>
      );
    },
  },

  {
    accessorKey: "providers_count",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Providers" param="name" />
    ),
    cell: ({ row }) => {
      const {
        relationships: { providers },
      } = getProviderData(row);
      return (
        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gray-100 dark:bg-gray-800">
          <span className="text-sm font-bold text-gray-900 dark:text-gray-100">
            {providers.meta.count}
          </span>
        </div>
      );
    },
  },

  {
    accessorKey: "roles_count",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Roles" param="roles" />
    ),
    cell: ({ row }) => {
      const {
        relationships: { roles },
      } = getProviderData(row);
      return (
        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gray-100 dark:bg-gray-800">
          <span className="text-sm font-bold text-gray-900 dark:text-gray-100">
            {roles.meta.count}
          </span>
        </div>
      );
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
