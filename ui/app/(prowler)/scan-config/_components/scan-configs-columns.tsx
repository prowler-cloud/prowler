"use client";

import { ColumnDef } from "@tanstack/react-table";
import { Pencil, Trash2 } from "lucide-react";

import { Button } from "@/components/shadcn";
import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { ScanConfigData } from "@/types/scan-configs";

export const createScanConfigsColumns = (
  onEdit: (config: ScanConfigData) => void,
  onDelete: (config: ScanConfigData) => void,
): ColumnDef<ScanConfigData>[] => [
  {
    accessorKey: "attributes.name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Name" />
    ),
    cell: ({ row }) => (
      <div className="max-w-[260px]">
        <p className="text-text-neutral-primary truncate text-sm font-medium">
          {row.original.attributes.name}
        </p>
      </div>
    ),
  },
  {
    id: "providers_count",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Accounts" />
    ),
    cell: ({ row }) => {
      const count = row.original.attributes.providers?.length ?? 0;
      return (
        <span className="text-text-neutral-primary text-sm">
          {count === 0 ? (
            <span className="text-text-neutral-tertiary italic">
              No accounts
            </span>
          ) : (
            `${count} ${count === 1 ? "account" : "accounts"}`
          )}
        </span>
      );
    },
    enableSorting: false,
  },
  {
    accessorKey: "attributes.updated_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Updated" />
    ),
    cell: ({ row }) => (
      <div className="w-[160px]">
        <DateWithTime dateTime={row.original.attributes.updated_at} />
      </div>
    ),
  },
  {
    id: "actions",
    header: () => null,
    cell: ({ row }) => (
      <div className="flex justify-end gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onEdit(row.original)}
          aria-label={`Edit ${row.original.attributes.name}`}
        >
          <Pencil className="size-4" />
          Edit
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onDelete(row.original)}
          aria-label={`Delete ${row.original.attributes.name}`}
        >
          <Trash2 className="size-4" />
        </Button>
      </div>
    ),
    enableSorting: false,
  },
];
