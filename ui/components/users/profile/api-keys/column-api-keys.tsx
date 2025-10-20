"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DataTableColumnHeader } from "@/components/ui/table";

import { DataTableRowActions } from "./data-table-row-actions";
import {
  DateCell,
  EmailCell,
  LastUsedCell,
  NameCell,
  PrefixCell,
  StatusCell,
} from "./table-cells";
import { EnrichedApiKey } from "./types";

export const createApiKeyColumns = (
  onEdit: (apiKey: EnrichedApiKey) => void,
  onRevoke: (apiKey: EnrichedApiKey) => void,
): ColumnDef<EnrichedApiKey>[] => [
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Name" param="name" />
    ),
    cell: ({ row }) => <NameCell apiKey={row.original} />,
  },
  {
    accessorKey: "prefix",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Prefix" param="prefix" />
    ),
    cell: ({ row }) => <PrefixCell apiKey={row.original} />,
  },
  {
    id: "email",
    header: "Email",
    cell: ({ row }) => <EmailCell apiKey={row.original} />,
    enableSorting: false,
  },
  {
    accessorKey: "inserted_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Created"
        param="inserted_at"
      />
    ),
    cell: ({ row }) => <DateCell date={row.original.attributes.inserted_at} />,
  },
  {
    accessorKey: "last_used_at",
    header: "Last Used",
    cell: ({ row }) => <LastUsedCell apiKey={row.original} />,
    enableSorting: false,
  },
  {
    accessorKey: "expires_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Expires"
        param="expires_at"
      />
    ),
    cell: ({ row }) => <DateCell date={row.original.attributes.expires_at} />,
  },
  {
    accessorKey: "revoked",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" param="revoked" />
    ),
    cell: ({ row }) => <StatusCell apiKey={row.original} />,
  },
  {
    id: "actions",
    header: "",
    cell: ({ row }) => {
      return (
        <DataTableRowActions row={row} onEdit={onEdit} onRevoke={onRevoke} />
      );
    },
  },
];
