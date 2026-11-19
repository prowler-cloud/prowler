"use client";

import type { ColumnDef } from "@tanstack/react-table";

import { ActorCell } from "@/app/(prowler)/realtime/_components/shared/actor-cell";
import { FitText } from "@/app/(prowler)/realtime/_components/shared/fit-text";
import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import { RealtimeEmptyState } from "@/app/(prowler)/realtime/_components/shared/realtime-empty-state";
import { RealtimeFilters } from "@/app/(prowler)/realtime/_components/shared/realtime-filters";
import { useUrlParam } from "@/app/(prowler)/realtime/_components/shared/use-url-param";
import {
  asSeverity,
  DETECTION_STATUS_LABELS,
  detectionStatusBadge,
  formatDateTime,
  isDriftDetection,
  SEVERITY_FILTER_LABELS,
  shortArn,
} from "@/app/(prowler)/realtime/_lib/display";
import { REALTIME_PARAM } from "@/app/(prowler)/realtime/_lib/routes";
import type {
  RealtimeAction,
  RealtimeDetection,
} from "@/app/(prowler)/realtime/_types";
import { Badge } from "@/components/shadcn";
import { DataTable, SeverityBadge } from "@/components/shadcn/table";
import { DetailSidePanel } from "@/components/side-panel/detail-side-panel";
import type { MetaDataProps } from "@/types";

import { DetectionDetail } from "./detection-detail";

const FILTERS = [
  {
    key: "status__in",
    label: "Verdict",
    values: Object.keys(DETECTION_STATUS_LABELS),
    labels: DETECTION_STATUS_LABELS,
  },
  {
    key: "severity__in",
    label: "Severity",
    values: Object.keys(SEVERITY_FILTER_LABELS),
    labels: SEVERITY_FILTER_LABELS,
  },
];

const columns: ColumnDef<RealtimeDetection>[] = [
  {
    accessorKey: "event_time",
    header: "Time",
    cell: ({ row }) => (
      <span className="text-text-neutral-tertiary text-xs whitespace-nowrap">
        {formatDateTime(row.original.event_time)}
      </span>
    ),
  },
  {
    accessorKey: "title",
    header: "Detection",
    cell: ({ row }) => (
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="text-text-neutral-primary flex flex-wrap items-center gap-2 text-sm font-medium">
          {row.original.title}
          {isDriftDetection(row.original) && (
            <Badge variant="tag" size="sm">
              Compliance drift
            </Badge>
          )}
        </span>
        <span
          title={[row.original.resource, row.original.region]
            .filter(Boolean)
            .join(" · ")}
        >
          <FitText className="text-text-neutral-tertiary font-mono text-xs">
            {[
              row.original.resource && shortArn(row.original.resource),
              row.original.region,
            ]
              .filter(Boolean)
              .join(" · ")}
          </FitText>
        </span>
      </div>
    ),
  },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => {
      const severity = asSeverity(row.original.severity);
      return severity ? (
        <SeverityBadge severity={severity} />
      ) : (
        <span className="text-xs">{row.original.severity}</span>
      );
    },
  },
  {
    accessorKey: "actor",
    header: "Actor",
    cell: ({ row }) => <ActorCell arn={row.original.actor} />,
  },
  {
    accessorKey: "status",
    header: "Verdict",
    cell: ({ row }) => (
      <RealtimeBadge descriptor={detectionStatusBadge(row.original.status)} />
    ),
  },
];

interface DetectionsTableProps {
  providerId: string;
  detections: RealtimeDetection[];
  metadata: MetaDataProps;
  selected: RealtimeDetection | null;
  selectedActions: RealtimeAction[];
  filtered: boolean;
}

export function DetectionsTable({
  providerId,
  detections,
  metadata,
  selected,
  selectedActions,
  filtered,
}: DetectionsTableProps) {
  const panel = useUrlParam(REALTIME_PARAM.DETECTION);

  return (
    <div className="flex flex-col gap-4">
      <RealtimeFilters filters={FILTERS} />
      {detections.length === 0 ? (
        <RealtimeEmptyState
          title={filtered ? "No detections match" : "No detections yet"}
          description={
            filtered
              ? "Change or clear the filters to see more detections."
              : "Detections appear here when a risky change in the account matches a rule. Prowler then checks the resource it touched."
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={detections}
          metadata={metadata}
          onRowClick={(row) => panel.set(row.original.id)}
        />
      )}
      <DetailSidePanel
        open={Boolean(panel.value)}
        onOpenChange={(open) => {
          if (!open) panel.clear();
        }}
        title="Detection details"
      >
        <DetectionDetail
          providerId={providerId}
          detection={selected}
          actions={selectedActions}
        />
      </DetailSidePanel>
    </div>
  );
}
