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

export const ColumnsProviders: ColumnDef<ProviderProps>[] = [
  {
    header: "ID",
    cell: ({ row }) => <p className="text-medium">{row.index + 1}</p>,
  },
  {
    accessorKey: "account",
    header: "Account",
    cell: ({ row }) => {
      const provider = row.original;
      return (
        <ProviderInfo
          connected={provider.attributes.connection.connected}
          provider={provider.attributes.provider}
          providerAlias={provider.attributes.alias}
          providerId={provider.attributes.provider_id}
        />
      );
    },
  },
  {
    accessorKey: "status",
    header: "Scan Status",
    cell: ({ row }) => {
      const provider = row.original;
      return <StatusBadge status={provider.attributes.status} />;
    },
  },
  {
    accessorKey: "lastScan",
    header: "Last Scan",
    cell: ({ row }) => {
      const provider = row.original;
      return <DateWithTime dateTime={provider.attributes.updated_at} />;
    },
  },
  {
    accessorKey: "nextScan",
    header: "Next Scan",
    cell: ({ row }) => {
      const provider = row.original;
      const nextDay = add(new Date(provider.attributes.updated_at), {
        hours: 24,
      });
      return <DateWithTime dateTime={nextDay.toISOString()} />;
    },
  },
  {
    accessorKey: "resources",
    header: "Resources",
    cell: ({ row }) => {
      const provider = row.original;
      return <p className="font-medium">{provider.attributes.resources}</p>;
    },
  },
  {
    accessorKey: "added",
    header: "Added",
    cell: ({ row }) => {
      const provider = row.original;
      return (
        <DateWithTime
          dateTime={provider.attributes.inserted_at}
          showTime={false}
        />
      );
    },
  },
  {
    accessorKey: "actions",
    header: () => <div className="text-right">Actions</div>,
    id: "actions",
    cell: () => {
      //   const provider = row.original;
      return (
        <div className="relative flex justify-end items-center gap-2">
          <Dropdown className="bg-background border-1 border-default-200">
            <DropdownTrigger>
              <Button isIconOnly radius="full" size="sm" variant="light">
                <VerticalDotsIcon className="text-default-400" />
              </Button>
            </DropdownTrigger>
            <DropdownMenu>
              <DropdownItem>Manage</DropdownItem>
              <DropdownItem>Delete</DropdownItem>
            </DropdownMenu>
          </Dropdown>
        </div>
      );
    },
  },
];
