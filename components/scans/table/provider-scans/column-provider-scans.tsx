"use client";

import { ColumnDef } from "@tanstack/react-table";

import { EntityInfoShort } from "@/components/ui/entities";
import { ProviderProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

const getProviderData = (row: { original: ProviderProps }) => {
  return row.original;
};

export const ColumnProviderScans: ColumnDef<ProviderProps>[] = [
  {
    accessorKey: "provider",
    header: "Provider",
    cell: ({ row }) => {
      const {
        attributes: { connection, provider, alias, uid },
      } = getProviderData(row);
      return (
        <EntityInfoShort
          connected={connection.connected}
          cloudProvider={provider}
          entityAlias={alias}
          entityId={uid}
        />
      );
    },
  },
  {
    accessorKey: "launchScan",
    header: "Launch Scan",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
