"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { PencilIcon, PowerIcon, TrashIcon } from "lucide-react";

import type { AlertRule } from "@/app/(prowler)/alerts/_types";
import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { DateWithTime } from "@/components/shadcn/entities";
import { DataTable } from "@/components/shadcn/table/data-table";
import { DataTableColumnHeader } from "@/components/shadcn/table/data-table-column-header";
import type { MetaDataProps } from "@/types";

interface AlertsTableProps {
  alerts: AlertRule[];
  meta?: MetaDataProps;
  mutatingId: string | null;
  onEdit: (alert: AlertRule) => void;
  onToggleEnabled: (alert: AlertRule) => void;
  onDelete: (alert: AlertRule) => void;
}

const TRIGGER_LABELS = {
  after_scan: "After each scan",
  daily: "Daily digest",
  both: "After scan and daily",
} as const satisfies Record<AlertRule["attributes"]["trigger"], string>;

const summarize = (first: string, count: number): string | null => {
  if (count === 0) return null;
  if (count === 1) return first;
  return `${first} +${count - 1} more`;
};

/** Both destination kinds share one compact cell (design D6). */
const formatDestinations = (alert: AlertRule): string => {
  const recipients = alert.attributes.recipient_emails ?? [];
  const channels = alert.attributes.slack_channels ?? [];

  const summaries = [
    summarize(recipients[0], recipients.length),
    summarize(channels[0] ? `#${channels[0].name}` : "", channels.length),
  ].filter((summary): summary is string => summary !== null);

  return summaries.length > 0 ? summaries.join(" · ") : "No destinations";
};

interface GetAlertsTableColumnsOptions {
  mutatingId: string | null;
  onEdit: (alert: AlertRule) => void;
  onToggleEnabled: (alert: AlertRule) => void;
  onDelete: (alert: AlertRule) => void;
}

const AlertActionsItems = ({
  alert,
  isMutating,
  onEdit,
  onToggleEnabled,
  onDelete,
}: {
  alert: AlertRule;
  isMutating: boolean;
  onEdit: (alert: AlertRule) => void;
  onToggleEnabled: (alert: AlertRule) => void;
  onDelete: (alert: AlertRule) => void;
}) => {
  const enabled = alert.attributes.enabled;
  const toggleLabel = enabled ? "Disable" : "Enable";

  return (
    <>
      <ActionDropdownItem
        icon={<PencilIcon />}
        label="Edit"
        onSelect={() => onEdit(alert)}
      />
      <ActionDropdownItem
        icon={<PowerIcon />}
        label={toggleLabel}
        disabled={isMutating}
        onSelect={() => onToggleEnabled(alert)}
      />
      <ActionDropdownDangerZone>
        <ActionDropdownItem
          icon={<TrashIcon />}
          label="Delete"
          destructive
          disabled={isMutating}
          onSelect={() => onDelete(alert)}
        />
      </ActionDropdownDangerZone>
    </>
  );
};

const getAlertsTableColumns = ({
  mutatingId,
  onEdit,
  onToggleEnabled,
  onDelete,
}: GetAlertsTableColumnsOptions): ColumnDef<AlertRule>[] => [
  {
    id: "name",
    size: 320,
    minSize: 280,
    accessorFn: (alert) => alert.attributes.name,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Name" param="name" />
    ),
    cell: ({ row }) => {
      const alert = row.original;
      return (
        <div className="flex w-[320px] max-w-[320px] min-w-0 flex-col gap-1">
          <button
            type="button"
            className="hover:text-button-tertiary block w-full min-w-0 truncate text-left font-medium transition-colors"
            onClick={() => onEdit(alert)}
          >
            {alert.attributes.name}
          </button>
          {alert.attributes.description && (
            <span
              className="text-text-neutral-secondary block w-full truncate text-xs"
              title={alert.attributes.description}
            >
              {alert.attributes.description}
            </span>
          )}
        </div>
      );
    },
  },
  {
    id: "enabled",
    size: 140,
    minSize: 120,
    accessorFn: (alert) => (alert.attributes.enabled ? "Enabled" : "Disabled"),
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" param="enabled" />
    ),
    cell: ({ row }) =>
      row.original.attributes.enabled ? "Enabled" : "Disabled",
  },
  {
    id: "trigger",
    size: 190,
    minSize: 170,
    accessorFn: (alert) => TRIGGER_LABELS[alert.attributes.trigger],
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Frequency"
        param="trigger"
      />
    ),
    cell: ({ row }) => TRIGGER_LABELS[row.original.attributes.trigger],
  },
  {
    id: "destinations",
    size: 220,
    minSize: 180,
    enableSorting: false,
    accessorFn: (alert) => formatDestinations(alert),
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Destinations" />
    ),
    cell: ({ row }) => formatDestinations(row.original),
  },
  {
    id: "inserted_at",
    size: 170,
    minSize: 150,
    accessorFn: (alert) => alert.attributes.inserted_at,
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Created at"
        param="inserted_at"
      />
    ),
    cell: ({ row }) => (
      <div className="w-[150px]">
        <DateWithTime dateTime={row.original.attributes.inserted_at} />
      </div>
    ),
  },
  {
    id: "updated_at",
    size: 170,
    minSize: 150,
    accessorFn: (alert) => alert.attributes.updated_at,
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Updated at"
        param="updated_at"
      />
    ),
    cell: ({ row }) => (
      <div className="w-[150px]">
        <DateWithTime dateTime={row.original.attributes.updated_at} />
      </div>
    ),
  },
  {
    id: "actions",
    size: 72,
    minSize: 64,
    enableSorting: false,
    cell: ({ row }) => {
      const alert = row.original;
      const isMutating = mutatingId === alert.id;
      return (
        <div className="flex items-center justify-end">
          <ActionDropdown ariaLabel={`Actions for ${alert.attributes.name}`}>
            <AlertActionsItems
              alert={alert}
              isMutating={isMutating}
              onEdit={onEdit}
              onToggleEnabled={onToggleEnabled}
              onDelete={onDelete}
            />
          </ActionDropdown>
        </div>
      );
    },
  },
];

export const AlertsTable = ({
  alerts,
  meta,
  mutatingId,
  onEdit,
  onToggleEnabled,
  onDelete,
}: AlertsTableProps) => (
  <DataTable
    columns={getAlertsTableColumns({
      mutatingId,
      onEdit,
      onToggleEnabled,
      onDelete,
    })}
    data={alerts}
    metadata={meta}
    showSearch
    searchPlaceholder="Search alerts"
  />
);
