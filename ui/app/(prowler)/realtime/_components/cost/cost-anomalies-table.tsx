"use client";

import type { ColumnDef } from "@tanstack/react-table";

import { RealtimeEmptyState } from "@/app/(prowler)/realtime/_components/shared/realtime-empty-state";
import { useUrlParam } from "@/app/(prowler)/realtime/_components/shared/use-url-param";
import {
  formatChange,
  formatMoney,
} from "@/app/(prowler)/realtime/_lib/display";
import { REALTIME_PARAM } from "@/app/(prowler)/realtime/_lib/routes";
import type {
  RealtimeAnomalyPayload,
  RealtimeCostAnomaly,
  RealtimeCostThresholds,
  RealtimeResult,
} from "@/app/(prowler)/realtime/_types";
import { DataTable } from "@/components/shadcn/table";
import { DetailSidePanel } from "@/components/side-panel/detail-side-panel";

import { AnomalyDetail } from "./anomaly-detail";

const columns: ColumnDef<RealtimeCostAnomaly>[] = [
  {
    accessorKey: "short_service",
    header: "Service",
    cell: ({ row }) => (
      <span className="text-text-neutral-primary text-sm font-medium">
        {row.original.short_service || row.original.service}
      </span>
    ),
  },
  {
    accessorKey: "region",
    header: "Region",
    cell: ({ row }) => (
      <span className="text-text-neutral-tertiary text-xs">
        {row.original.region}
      </span>
    ),
  },
  {
    accessorKey: "today",
    header: "Latest day",
    cell: ({ row }) => formatMoney(row.original.today),
  },
  {
    accessorKey: "base",
    header: "Baseline",
    cell: ({ row }) => formatMoney(row.original.base),
  },
  {
    id: "change",
    header: "Change",
    cell: ({ row }) => (
      <span className="text-text-warning-primary text-sm font-semibold whitespace-nowrap">
        {formatChange(row.original.ratio, row.original.delta)}
      </span>
    ),
  },
];

interface CostAnomaliesTableProps {
  anomalies: RealtimeCostAnomaly[];
  /** The anomaly open in the side panel, as the server loaded it. */
  anomaly: RealtimeResult<RealtimeAnomalyPayload> | null;
  thresholds: RealtimeCostThresholds;
}

export function CostAnomaliesTable({
  anomalies,
  anomaly,
  thresholds,
}: CostAnomaliesTableProps) {
  const panel = useUrlParam(REALTIME_PARAM.ANOMALY);

  return (
    <>
      {anomalies.length === 0 ? (
        <RealtimeEmptyState
          title="No anomalies"
          description="Spend in every service and region is within the thresholds."
        />
      ) : (
        <DataTable
          columns={columns}
          data={anomalies}
          onRowClick={(row) => panel.set(row.original.id)}
        />
      )}
      <DetailSidePanel
        open={Boolean(panel.value)}
        onOpenChange={(open) => {
          if (!open) panel.clear();
        }}
        title="Cost anomaly details"
      >
        <AnomalyDetail result={anomaly} fallbackThresholds={thresholds} />
      </DetailSidePanel>
    </>
  );
}
