"use client";

import type { ColumnDef } from "@tanstack/react-table";

import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import { RealtimeEmptyState } from "@/app/(prowler)/realtime/_components/shared/realtime-empty-state";
import { RealtimeFilters } from "@/app/(prowler)/realtime/_components/shared/realtime-filters";
import { useUrlParam } from "@/app/(prowler)/realtime/_components/shared/use-url-param";
import {
  ACTION_KIND_LABELS,
  ACTION_STATUS_LABELS,
  actionKindLabel,
  actionStatusBadge,
  formatDateTime,
  isLighthouseAction,
} from "@/app/(prowler)/realtime/_lib/display";
import { REALTIME_PARAM } from "@/app/(prowler)/realtime/_lib/routes";
import {
  REALTIME_ACTION_KIND,
  type RealtimeAction,
} from "@/app/(prowler)/realtime/_types";
import { Badge, Button } from "@/components/shadcn";
import { DataTable } from "@/components/shadcn/table";
import { DetailSidePanel } from "@/components/side-panel/detail-side-panel";
import type { MetaDataProps } from "@/types";

import { ActionDetail } from "./action-detail";
import { ActionResult } from "./action-result";
import { RevertActionButton } from "./revert-action-button";

const KIND_PARAM = "filter[kind__in]";

const KIND_OPTIONS = [
  { value: null, label: "All" },
  ...Object.values(REALTIME_ACTION_KIND).map((kind) => ({
    value: kind,
    label: ACTION_KIND_LABELS[kind],
  })),
];

const STATUS_FILTERS = [
  {
    key: "status__in",
    label: "Status",
    values: Object.keys(ACTION_STATUS_LABELS),
    labels: ACTION_STATUS_LABELS,
  },
];

const getColumns = ({
  providerId,
  canWrite,
  demo,
}: {
  providerId: string;
  canWrite: boolean;
  demo: boolean;
}): ColumnDef<RealtimeAction>[] => [
  {
    accessorKey: "inserted_at",
    header: "When",
    cell: ({ row }) => (
      <span className="text-text-neutral-tertiary text-xs whitespace-nowrap">
        {formatDateTime(row.original.inserted_at)}
      </span>
    ),
  },
  {
    accessorKey: "kind",
    header: "Action",
    cell: ({ row }) => (
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="text-text-neutral-primary flex flex-wrap items-center gap-2 text-sm font-medium">
          {actionKindLabel(row.original.kind)}
          {isLighthouseAction(row.original) && (
            <Badge variant="lighthouse" size="sm">
              Lighthouse AI
            </Badge>
          )}
        </span>
        <span className="text-text-neutral-tertiary truncate font-mono text-xs">
          {row.original.check_id}
        </span>
      </div>
    ),
  },
  {
    accessorKey: "resource_uid",
    header: "Resource",
    cell: ({ row }) => (
      <div className="flex flex-col gap-0.5">
        <span className="text-text-neutral-secondary font-mono text-xs break-all">
          {row.original.resource_uid}
        </span>
        <span className="text-text-neutral-tertiary text-xs">
          {row.original.region}
        </span>
      </div>
    ),
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => (
      <RealtimeBadge descriptor={actionStatusBadge(row.original.status)} />
    ),
  },
  {
    id: "result",
    header: "Result",
    cell: ({ row }) => (
      <ActionResult action={row.original} providerId={providerId} />
    ),
  },
  {
    id: "revert",
    header: () => <span className="sr-only">Revert</span>,
    cell: ({ row }) =>
      row.original.revertible ? (
        <div className="flex justify-end">
          <RevertActionButton
            action={row.original}
            canWrite={canWrite}
            demo={demo}
          />
        </div>
      ) : null,
  },
];

interface RemediationTableProps {
  providerId: string;
  actions: RealtimeAction[];
  metadata: MetaDataProps;
  selected: RealtimeAction | null;
  canWrite: boolean;
  demo: boolean;
  filtered: boolean;
}

export function RemediationTable({
  providerId,
  actions,
  metadata,
  selected,
  canWrite,
  demo,
  filtered,
}: RemediationTableProps) {
  const kind = useUrlParam(KIND_PARAM);
  const panel = useUrlParam(REALTIME_PARAM.ACTION);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <div
          role="group"
          aria-label="Kind of action"
          className="border-border-neutral-secondary flex flex-wrap gap-1 rounded-lg border p-1"
        >
          {KIND_OPTIONS.map((option) => {
            const active = (kind.value ?? null) === option.value;
            return (
              <Button
                key={option.label}
                size="sm"
                variant={active ? "secondary" : "ghost"}
                aria-pressed={active}
                onClick={() =>
                  option.value ? kind.set(option.value) : kind.clear()
                }
              >
                {option.label}
              </Button>
            );
          })}
        </div>
        <RealtimeFilters filters={STATUS_FILTERS} />
      </div>

      {actions.length === 0 ? (
        <RealtimeEmptyState
          title={filtered ? "No actions match" : "No actions yet"}
          description={
            filtered
              ? "Change or clear the filters to see more actions."
              : "Fixes, pull requests and proposals appear here once a violation is confirmed and the policy responds to it."
          }
        />
      ) : (
        <DataTable
          columns={getColumns({ providerId, canWrite, demo })}
          data={actions}
          metadata={metadata}
          onRowClick={(row) => panel.set(row.original.id)}
        />
      )}

      <DetailSidePanel
        open={Boolean(panel.value)}
        onOpenChange={(open) => {
          if (!open) panel.clear();
        }}
        title="Action details"
      >
        <ActionDetail
          providerId={providerId}
          action={selected}
          canWrite={canWrite}
          demo={demo}
        />
      </DetailSidePanel>
    </div>
  );
}
