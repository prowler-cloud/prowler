"use client";

import { ColumnDef } from "@tanstack/react-table";
import { Pencil, Trash2 } from "lucide-react";

import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { DateWithTime } from "@/components/shadcn/entities";
import { DataTableColumnHeader } from "@/components/shadcn/table";
import { ScanConfigurationData } from "@/types/scan-configurations";

export const createScanConfigurationsColumns = (
  onEdit: (config: ScanConfigurationData) => void,
  onDelete: (config: ScanConfigurationData) => void,
): ColumnDef<ScanConfigurationData>[] => [
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
      <DataTableColumnHeader column={column} title="Providers" />
    ),
    cell: ({ row }) => {
      const count = row.original.attributes.providers?.length ?? 0;
      return (
        <span className="text-text-neutral-primary text-sm">
          {count === 0 ? (
            <span className="text-text-neutral-tertiary italic">
              No providers
            </span>
          ) : (
            `${count} ${count === 1 ? "provider" : "providers"}`
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
      <div className="relative flex items-center justify-end gap-2">
        <ActionDropdown
          ariaLabel={`Open actions menu for ${row.original.attributes.name}`}
        >
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit"
            onSelect={() => onEdit(row.original)}
          />
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Delete"
              destructive
              onSelect={() => onDelete(row.original)}
            />
          </ActionDropdownDangerZone>
        </ActionDropdown>
      </div>
    ),
    enableSorting: false,
  },
];
