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
import { StatusBadge } from "@/components/ui";
import { ProviderProps } from "@/types";

import { CheckConnectionProvider } from "../CheckConnectionProvider";
import { DateWithTime } from "../DateWithTime";
import { DeleteProvider } from "../DeleteProvider";
import { ProviderInfo } from "../ProviderInfo";
import { DataTableColumnHeader } from "./DataTableColumnHeader";

const getProviderData = (row: { original: ProviderProps }) => {
  return row.original;
};

export const ColumnsProvider: ColumnDef<ProviderProps>[] = [
  {
    header: "ID",
    cell: ({ row }) => <p className="text-medium">{row.index + 1}</p>,
  },
  {
    accessorKey: "account",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Account"} param="alias" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { connection, provider, alias, provider_id },
      } = getProviderData(row);
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
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Last Scan"}
        param="updated_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { updated_at },
      } = getProviderData(row);
      return <DateWithTime dateTime={updated_at} />;
    },
  },
  {
    accessorKey: "nextScan",
    header: "Next Scan",
    cell: ({ row }) => {
      const {
        attributes: { updated_at },
      } = getProviderData(row);
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
    accessorKey: "actions",
    header: () => <div className="text-right">Actions</div>,
    id: "actions",
    cell: ({ row }) => {
      const { id } = getProviderData(row);
      return (
        <div className="relative flex justify-end items-center gap-2">
          <Dropdown className="bg-background border-1 border-default-200">
            <DropdownTrigger>
              <Button isIconOnly radius="full" size="sm" variant="light">
                <VerticalDotsIcon className="text-default-400" />
              </Button>
            </DropdownTrigger>
            <DropdownMenu>
              <DropdownItem textValue="Check Connection">
                <CheckConnectionProvider id={id} />
              </DropdownItem>
              <DropdownItem textValue="Delete Provider">
                <DeleteProvider id={id} />
              </DropdownItem>
            </DropdownMenu>
          </Dropdown>
        </div>
      );
    },
  },
];
