"use client";

import { ColumnDef } from "@tanstack/react-table";

import { AddIcon } from "@/components/icons/Icons";
import { CustomButton } from "@/components/ui/custom";
import { EntityInfoShort } from "@/components/ui/entities";
import { ProviderProps } from "@/types";

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
      return (
        <CustomButton
          className="w-full"
          ariaLabel="Start Scan"
          variant="solid"
          color="action"
          size="md"
          endContent={<AddIcon size={20} />}
          onPress={() => {
            console.log(row.original.id);
          }}
        >
          Start
        </CustomButton>
      );
    },
  },
];
