"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { ArrowUp } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { ActorCell } from "@/app/(prowler)/realtime/_components/shared/actor-cell";
import { FitText } from "@/app/(prowler)/realtime/_components/shared/fit-text";
import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import { RealtimeEmptyState } from "@/app/(prowler)/realtime/_components/shared/realtime-empty-state";
import { useUrlParam } from "@/app/(prowler)/realtime/_components/shared/use-url-param";
import {
  detectionStatusBadge,
  formatDateTime,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  REALTIME_PARAM,
  REALTIME_TAB,
  realtimeHref,
} from "@/app/(prowler)/realtime/_lib/routes";
import type { RealtimeEvent } from "@/app/(prowler)/realtime/_types";
import { Button, Label, Switch } from "@/components/shadcn";
import { DataTable } from "@/components/shadcn/table";

/** Rows to show and how many arrived since the snapshot was taken. */
export const followView = (
  events: RealtimeEvent[],
  snapshot: string[] | null,
): { visible: RealtimeEvent[]; newCount: number } => {
  if (snapshot === null) return { visible: events, newCount: 0 };
  const known = new Set(snapshot);
  return {
    visible: events.filter((event) => known.has(event.id)),
    newCount: events.filter((event) => !known.has(event.id)).length,
  };
};

const getColumns = (providerId: string): ColumnDef<RealtimeEvent>[] => [
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
    accessorKey: "event_name",
    header: "Event",
    cell: ({ row }) => {
      const { event_name: name, event_source: source } = row.original;
      const error = row.original.error_code;
      return (
        <div
          className="flex min-w-0 flex-col gap-0.5"
          title={[name, source, error].filter(Boolean).join(" · ")}
        >
          <span className="text-text-neutral-primary font-mono text-xs wrap-anywhere">
            {name}
          </span>
          <FitText className="text-text-neutral-tertiary text-xs">
            {source}
          </FitText>
          {error && (
            <FitText className="text-text-error-primary text-xs">
              {error}
            </FitText>
          )}
        </div>
      );
    },
  },
  {
    accessorKey: "user_arn",
    header: "Actor",
    cell: ({ row }) => <ActorCell arn={row.original.user_arn} />,
  },
  {
    accessorKey: "region",
    header: "Region",
    cell: ({ row }) => (
      <span className="text-text-neutral-tertiary text-xs whitespace-nowrap">
        {row.original.region}
      </span>
    ),
  },
  {
    accessorKey: "source_ip",
    header: "Source IP",
    cell: ({ row }) => (
      <span title={row.original.source_ip}>
        <FitText className="text-text-neutral-secondary font-mono text-xs">
          {row.original.source_ip}
        </FitText>
      </span>
    ),
  },
  {
    id: "detection",
    header: "Detection",
    cell: ({ row }) => {
      const { detection_status: status, rule_id: ruleId } = row.original;
      if (!status) {
        return <span className="text-text-neutral-tertiary text-xs">—</span>;
      }
      return (
        <Link
          href={realtimeHref(providerId, REALTIME_TAB.DETECTIONS, {
            "filter[rule_id]": ruleId ?? undefined,
          })}
          className="flex min-w-0 flex-col items-start gap-0.5"
          title={ruleId ?? undefined}
        >
          <RealtimeBadge descriptor={detectionStatusBadge(status)} />
          {ruleId && (
            <FitText className="text-text-neutral-tertiary font-mono text-xs">
              {ruleId}
            </FitText>
          )}
        </Link>
      );
    },
  },
];

interface StreamViewProps {
  providerId: string;
  events: RealtimeEvent[];
  showAll: boolean;
}

export function StreamView({ providerId, events, showAll }: StreamViewProps) {
  const allEvents = useUrlParam(REALTIME_PARAM.ALL_EVENTS);
  // Local state needed: null follows the live list, ids freeze what is shown.
  const [snapshot, setSnapshot] = useState<string[] | null>(null);
  const { visible, newCount } = followView(events, snapshot);
  const takeSnapshot = () => setSnapshot(events.map((event) => event.id));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div className="flex items-center gap-2">
          <Switch
            id="realtime-changes-only"
            checked={!showAll}
            onCheckedChange={(checked) =>
              checked ? allEvents.clear() : allEvents.set("1")
            }
          />
          <Label htmlFor="realtime-changes-only">Changes only</Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch
            id="realtime-follow-live"
            checked={snapshot === null}
            onCheckedChange={(checked) =>
              checked ? setSnapshot(null) : takeSnapshot()
            }
          />
          <Label htmlFor="realtime-follow-live">Follow live</Label>
        </div>
        <span className="text-text-neutral-tertiary text-xs">
          Last 24 hours, newest first
        </span>
        {newCount > 0 && (
          <div className="ml-auto">
            <Button variant="outline" size="sm" onClick={takeSnapshot}>
              <ArrowUp />
              {newCount === 1 ? "1 new event" : `${newCount} new events`}
            </Button>
          </div>
        )}
      </div>

      {visible.length === 0 ? (
        <RealtimeEmptyState
          title="No events in the last 24 hours"
          description={
            showAll
              ? "Prowler has not received any CloudTrail event from this account yet. Check the feed above."
              : "No changes were recorded. Turn off “Changes only” to see read-only calls too."
          }
        />
      ) : (
        <DataTable columns={getColumns(providerId)} data={visible} />
      )}
    </div>
  );
}
