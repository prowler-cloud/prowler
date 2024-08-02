"use client";

import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
} from "@nextui-org/react";
import { ColumnDef } from "@tanstack/react-table";
import { add } from "date-fns";

import { VerticalDotsIcon } from "@/components/icons";
import { StatusBadge } from "@/components/ui/table/StatusBadge";
import { ProviderProps } from "@/types";

import { DateWithTime } from "../DateWithTime";
import { ProviderInfo } from "../ProviderInfo";

const getProviderAttributes = (row: { original: ProviderProps }) => {
  return row.original.attributes;
};

export const ColumnsProviders: ColumnDef<ProviderProps>[] = [
  {
    header: "ID",
    cell: ({ row }) => <p className="text-medium">{row.index + 1}</p>,
  },
  {
    accessorKey: "account",
    header: "Account",
    cell: ({ row }) => {
      const { connection, provider, alias, provider_id } =
        getProviderAttributes(row);
      return (
        <ProviderInfo
          connected={connection.connected}
          provider={provider}
          providerAlias={alias}
          providerId={provider_id}
        />
      );
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
    header: "Last Scan",
    cell: ({ row }) => {
      const { updated_at } = getProviderAttributes(row);
      return <DateWithTime dateTime={updated_at} />;
    },
  },
  {
    accessorKey: "nextScan",
    header: "Next Scan",
    cell: ({ row }) => {
      const { updated_at } = getProviderAttributes(row);
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
    header: "Added",
    cell: ({ row }) => {
      const { inserted_at } = getProviderAttributes(row);
      return <DateWithTime dateTime={inserted_at} showTime={false} />;
    },
  },
  {
    accessorKey: "actions",
    header: () => <div className="text-right">Actions</div>,
    id: "actions",
    cell: () => {
      return (
        <div className="relative flex justify-end items-center gap-2">
          <Dropdown className="bg-background border-1 border-default-200">
            <DropdownTrigger>
              <Button isIconOnly radius="full" size="sm" variant="light">
                <VerticalDotsIcon className="text-default-400" />
              </Button>
            </DropdownTrigger>
            <DropdownMenu>
              <DropdownItem>Check connection</DropdownItem>
              <DropdownItem>Manage</DropdownItem>
              <DropdownItem>Delete</DropdownItem>
            </DropdownMenu>
          </Dropdown>
        </div>
      );
    },
  },
];
