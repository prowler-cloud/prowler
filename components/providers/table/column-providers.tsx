"use client";

import { ColumnDef } from "@tanstack/react-table";
import { add } from "date-fns";

import { DateWithTime, SnippetId } from "@/components/ui/entities";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { ProviderProps } from "@/types";

import { ProviderInfo } from "../provider-info";
import { DataTableRowActions } from "./data-table-row-actions";

const getProviderData = (row: { original: ProviderProps }) => {
  return row.original;
};

export const ColumnProviders: ColumnDef<ProviderProps>[] = [
  {
    header: " ",
    cell: ({ row }) => <p className="text-medium">{row.index + 1}</p>,
  },
  {
    accessorKey: "account",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Account"} param="alias" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { connection, provider, alias },
      } = getProviderData(row);
      return (
        <ProviderInfo
          connected={connection.connected}
          provider={provider}
          providerAlias={alias}
        />
      );
    },
  },
  {
    accessorKey: "uid",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Id"} param="uid" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { uid },
      } = getProviderData(row);
      return <SnippetId className="h-7 max-w-48" entityId={uid} />;
    },
  },
  {
    accessorKey: "status",
    header: "Scan Status",
    cell: () => {
      // Temporarily overwriting the value until the API is functional.
      return <StatusBadge status={"completed"} />;
    },
  },
  {
    accessorKey: "lastScan",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Last Scan"}
        param="updated_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { updated_at },
      } = getProviderData(row);
      return <DateWithTime dateTime={updated_at} />;
    },
  },
  {
    accessorKey: "nextScan",
    header: "Next Scan",
    cell: ({ row }) => {
      const {
        attributes: { updated_at },
      } = getProviderData(row);
      const nextDay = add(new Date(updated_at), {
        hours: 24,
      });
      return <DateWithTime dateTime={nextDay.toISOString()} />;
    },
  },
  {
    accessorKey: "resources",
    header: "Resources",
    cell: () => {
      // Temporarily overwriting the value until the API is functional.
      return <p className="font-medium">{288}</p>;
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
