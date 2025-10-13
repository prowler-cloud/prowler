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
      <DataTableColumnHeader column={column} title="NAME" param="name" />
    ),
    cell: ({ row }) => <NameCell apiKey={row.original} />,
  },
  {
    accessorKey: "prefix",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="PREFIX" param="prefix" />
    ),
    cell: ({ row }) => <PrefixCell apiKey={row.original} />,
  },
  {
    id: "email",
    header: "EMAIL",
    cell: ({ row }) => <EmailCell apiKey={row.original} />,
    enableSorting: false,
  },
  {
    accessorKey: "inserted_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="CREATED"
        param="inserted_at"
      />
    ),
    cell: ({ row }) => <DateCell date={row.original.attributes.inserted_at} />,
  },
  {
    accessorKey: "last_used_at",
    header: "LAST USED",
    cell: ({ row }) => <LastUsedCell apiKey={row.original} />,
    enableSorting: false,
  },
  {
    accessorKey: "expires_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="EXPIRES"
        param="expires_at"
      />
    ),
    cell: ({ row }) => <DateCell date={row.original.attributes.expires_at} />,
  },
  {
    accessorKey: "revoked",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="STATUS" param="revoked" />
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
