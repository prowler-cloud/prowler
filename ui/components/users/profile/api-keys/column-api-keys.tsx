"use client";

import { ColumnDef } from "@tanstack/react-table";

import { type EnrichedApiKey } from "@/actions/api-keys/api-keys.adapter";
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

export const createApiKeyColumns = (
  onEdit: (apiKey: EnrichedApiKey) => void,
  onDelete: (apiKey: EnrichedApiKey) => void,
): ColumnDef<EnrichedApiKey>[] => [
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="NAME" />
    ),
    cell: ({ row }) => <NameCell apiKey={row.original} />,
  },
  {
    accessorKey: "prefix",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="PREFIX" />
    ),
    cell: ({ row }) => <PrefixCell apiKey={row.original} />,
  },
  {
    id: "email",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="EMAIL" />
    ),
    cell: ({ row }) => <EmailCell apiKey={row.original} />,
  },
  {
    accessorKey: "inserted_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="CREATED" />
    ),
    cell: ({ row }) => <DateCell date={row.original.attributes.inserted_at} />,
  },
  {
    accessorKey: "last_used_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="LAST USED" />
    ),
    cell: ({ row }) => <LastUsedCell apiKey={row.original} />,
  },
  {
    accessorKey: "expires_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="EXPIRES" />
    ),
    cell: ({ row }) => <DateCell date={row.original.attributes.expires_at} />,
  },
  {
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="STATUS" />
    ),
    cell: ({ row }) => <StatusCell apiKey={row.original} />,
  },
  {
    id: "actions",
    header: "Actions",
    cell: ({ row }) => {
      return (
        <DataTableRowActions row={row} onEdit={onEdit} onDelete={onDelete} />
      );
    },
  },
];
