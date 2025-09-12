"use client";

import { Chip } from "@nextui-org/react";
import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime, SnippetChip } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { ProviderProps } from "@/types";

import { LinkToScans } from "../link-to-scans";
import { ProviderInfo } from "../provider-info";
import { DataTableRowActions } from "./data-table-row-actions";

interface GroupNameChipsProps {
  groupNames?: string[];
}

const getProviderData = (row: { original: ProviderProps }) => {
  const provider = row.original;
  return {
    attributes: provider.attributes,
    groupNames: provider.groupNames,
  };
};

export const ColumnProviders: ColumnDef<ProviderProps>[] = [
  {
    accessorKey: "account",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Provider"} param="alias" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { connection, provider, alias, uid },
      } = getProviderData(row);
      return (
        <ProviderInfo
          connected={connection.connected}
          provider={provider}
          providerAlias={alias}
          providerUID={uid}
        />
      );
    },
  },
  {
    accessorKey: "scanJobs",
    header: "Scan Jobs",
    cell: ({ row }) => {
      const {
        attributes: { uid },
      } = getProviderData(row);
      return <LinkToScans providerUid={uid} />;
    },
  },
  {
    accessorKey: "groupNames",
    header: "Groups",
    cell: ({ row }) => {
      const { groupNames } = getProviderData(row);
      return <GroupNameChips groupNames={groupNames || []} />;
    },
  },
  {
    accessorKey: "uid",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Provider UID"}
        param="uid"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { uid },
      } = getProviderData(row);
      return <SnippetChip value={uid} className="h-7" />;
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
    id: "actions",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];

export const GroupNameChips: React.FC<GroupNameChipsProps> = ({
  groupNames,
}) => {
  return (
    <div className="flex max-w-[300px] flex-wrap gap-1">
      {groupNames?.map((name, index) => (
        <Chip
          key={index}
          size="sm"
          variant="flat"
          classNames={{
            base: "bg-default-100",
          }}
        >
          {name}
        </Chip>
      ))}
    </div>
  );
};
