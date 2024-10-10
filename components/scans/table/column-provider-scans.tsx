"use client";

import { ColumnDef } from "@tanstack/react-table";

import { AddIcon } from "@/components/icons/Icons";
import { ProviderInfoShort } from "@/components/providers";
import { CustomButton } from "@/components/ui/custom";
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
        <ProviderInfoShort
          connected={connection.connected}
          provider={provider}
          providerAlias={alias}
          providerId={uid}
        />
      );
    },
  },
  {
    accessorKey: "launchScan",
    header: "Launch Scan",
    cell: ({ row }) => {
      const {
        attributes: { uid },
      } = getProviderData(row);
      return (
        <CustomButton
          className="w-full"
          ariaLabel="Start Scan"
          variant="solid"
          color="action"
          size="md"
          endContent={<AddIcon size={20} />}
          onPress={() => {
            console.log(uid);
          }}
        >
          Start
        </CustomButton>
      );
    },
  },
];
