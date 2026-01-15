"use client";

import { ColumnDef } from "@tanstack/react-table";

import { MuteRuleData } from "@/actions/mute-rules/types";
import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";

import { MuteRuleEnabledToggle } from "./mute-rule-enabled-toggle";
import { MuteRuleRowActions } from "./mute-rule-row-actions";

export const createMuteRulesColumns = (
  onEdit: (muteRule: MuteRuleData) => void,
  onDelete: (muteRule: MuteRuleData) => void,
): ColumnDef<MuteRuleData>[] => [
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Name" />
    ),
    cell: ({ row }) => {
      const name = row.original.attributes.name;
      return (
        <div className="max-w-[200px]">
          <p className="truncate text-sm font-medium">{name}</p>
        </div>
      );
    },
  },
  {
    accessorKey: "reason",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Reason" />
    ),
    cell: ({ row }) => {
      const reason = row.original.attributes.reason;
      return (
        <div className="max-w-[300px]">
          <p className="truncate text-sm text-slate-600 dark:text-slate-400">
            {reason}
          </p>
        </div>
      );
    },
    enableSorting: false,
  },
  {
    accessorKey: "finding_count",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Findings" />
    ),
    cell: ({ row }) => {
      const count = row.original.attributes.finding_uids?.length || 0;
      return (
        <div className="w-[80px]">
          <span className="rounded-full bg-slate-100 px-2 py-1 text-xs font-medium dark:bg-slate-800">
            {count}
          </span>
        </div>
      );
    },
    enableSorting: false,
  },
  {
    accessorKey: "inserted_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Created"
        param="inserted_at"
      />
    ),
    cell: ({ row }) => {
      const insertedAt = row.original.attributes.inserted_at;
      return (
        <div className="w-[120px]">
          <DateWithTime dateTime={insertedAt} />
        </div>
      );
    },
  },
  {
    accessorKey: "enabled",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Enabled" />
    ),
    cell: ({ row }) => {
      return <MuteRuleEnabledToggle muteRule={row.original} />;
    },
    enableSorting: false,
  },
  {
    id: "actions",
    header: () => null,
    cell: ({ row }) => {
      return (
        <MuteRuleRowActions
          muteRule={row.original}
          onEdit={onEdit}
          onDelete={onDelete}
        />
      );
    },
    enableSorting: false,
  },
];
