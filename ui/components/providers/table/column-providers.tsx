"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime, SnippetId } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { ProviderProps } from "@/types";

import { LinkToScans } from "../link-to-scans";
import { ProviderInfo } from "../provider-info";
import { DataTableRowActions } from "./data-table-row-actions";

const getProviderData = (row: { original: ProviderProps }) => {
  return row.original;
};

export const ColumnProviders: ColumnDef<ProviderProps>[] = [
  {
    accessorKey: "account",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Account"} param="alias" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { connection, provider, alias, uid },
      } = getProviderData(row);
      return (
        <ProviderInfo
          connected={connection.connected}
          provider={provider}
          providerAlias={alias}
          providerUID={uid}
        />
      );
    },
  },
  {
    accessorKey: "scanJobs",
    header: "Scan Jobs",
    cell: ({ row }) => {
      const {
        attributes: { uid },
      } = getProviderData(row);
      return <LinkToScans providerUid={uid} />;
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
