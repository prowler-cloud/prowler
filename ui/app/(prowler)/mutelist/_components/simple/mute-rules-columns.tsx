"use client";

import { ColumnDef } from "@tanstack/react-table";
import { List } from "lucide-react";

import { MuteRuleData } from "@/actions/mute-rules/types";
import { Button, Checkbox } from "@/components/shadcn";
import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";

import { MuteRuleEnabledToggle } from "./mute-rule-enabled-toggle";
import { MuteRuleRowActions } from "./mute-rule-row-actions";
import { MuteRuleTableData } from "./mute-rule-target-previews";

export const createMuteRulesColumns = (
  onEdit: (muteRule: MuteRuleData) => void,
  onDelete: (muteRule: MuteRuleData) => void,
  onViewTargets: (muteRule: MuteRuleTableData) => void,
): ColumnDef<MuteRuleTableData>[] => [
  {
    id: "select",
    header: ({ table }) => (
      <Checkbox
        size="sm"
        checked={
          table.getIsAllPageRowsSelected()
            ? true
            : table.getIsSomePageRowsSelected()
              ? "indeterminate"
              : false
        }
        onCheckedChange={(checked) =>
          table.toggleAllPageRowsSelected(checked === true)
        }
        onClick={(event) => event.stopPropagation()}
        aria-label="Select all rules on this page"
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        size="sm"
        checked={row.getIsSelected()}
        onCheckedChange={(checked) => row.toggleSelected(checked === true)}
        onClick={(event) => event.stopPropagation()}
        aria-label={`Select ${row.original.attributes.name}`}
      />
    ),
    size: 40,
    enableSorting: false,
    enableHiding: false,
  },
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Name" />
    ),
    cell: ({ row }) => {
      const name = row.original.attributes.name;
      return (
        <div className="max-w-[200px]">
          <p className="text-text-neutral-primary truncate text-sm font-medium">
            {name}
          </p>
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
          <p className="text-text-neutral-tertiary truncate text-sm">
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
      const summaryLabel = row.original.targetSummaryLabel;
      const extraCount = Math.max(count - 1, 0);

      return (
        <Button
          variant="outline"
          onClick={() => onViewTargets(row.original)}
          className="h-auto max-w-[290px] justify-start gap-2 px-3 py-2"
          aria-label={`View muted findings for ${row.original.attributes.name}`}
        >
          <span className="border-border-neutral-secondary bg-bg-neutral-tertiary text-text-neutral-primary inline-flex h-5 min-w-5 shrink-0 items-center justify-center rounded-full border px-1.5 text-xs font-semibold">
            {count}
          </span>
          <span className="text-text-neutral-primary min-w-0 flex-1 truncate text-left text-sm font-medium">
            {summaryLabel}
          </span>
          {extraCount > 0 ? (
            <span className="text-text-neutral-tertiary shrink-0 text-xs font-medium">
              +{extraCount} more
            </span>
          ) : null}
          <List className="text-button-tertiary size-4 shrink-0" />
        </Button>
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
