import type { ReactNode } from "react";

import {
  REALTIME_ACTION_STATUS,
  REALTIME_DETECTION_STATUS,
  type RealtimeOverviewPayload,
} from "@/app/(prowler)/realtime/_types";
import { Card, CardContent, Progress } from "@/components/shadcn";

interface KpiCardProps {
  label: string;
  value: ReactNode;
  children?: ReactNode;
}

function KpiCard({ label, value, children }: KpiCardProps) {
  return (
    <Card variant="base" padding="lg">
      <CardContent className="flex flex-col gap-2">
        <span className="text-text-neutral-tertiary text-xs">{label}</span>
        <span className="text-text-neutral-primary text-3xl font-bold">
          {value}
        </span>
        {children}
      </CardContent>
    </Card>
  );
}

const count = (counts: Record<string, number> | undefined, key: string) =>
  counts?.[key] ?? 0;

interface OverviewKpisProps {
  overview: RealtimeOverviewPayload;
}

/** The four numbers that say how the account is doing right now. */
export function OverviewKpis({ overview }: OverviewKpisProps) {
  const { posture, detections, actions, events_last_hour: events } = overview;
  const checked = posture.passed + posture.failed;

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <KpiCard
        label="Posture score"
        value={posture.score === null ? "—" : `${Math.round(posture.score)}%`}
      >
        {posture.has_scan && checked > 0 ? (
          <>
            <Progress
              value={(posture.passed / checked) * 100}
              aria-label="Passing checks"
            />
            <span className="text-text-neutral-tertiary text-xs">
              {posture.passed.toLocaleString()} passed ·{" "}
              {posture.failed.toLocaleString()} failed
            </span>
          </>
        ) : (
          <span className="text-text-neutral-tertiary text-xs">
            Fills in after the first completed scan.
          </span>
        )}
      </KpiCard>
      <KpiCard
        label="Open violations"
        value={count(detections, REALTIME_DETECTION_STATUS.VIOLATION)}
      >
        <span className="text-text-neutral-tertiary text-xs">
          {count(detections, REALTIME_DETECTION_STATUS.NEW)} waiting for
          verification
        </span>
      </KpiCard>
      <KpiCard
        label="Fixed and verified"
        value={count(actions, REALTIME_ACTION_STATUS.FIXED_VERIFIED)}
      >
        <span className="text-text-neutral-tertiary text-xs">
          {count(actions, REALTIME_ACTION_STATUS.APPLIED)} waiting for re-check
          · {count(actions, REALTIME_ACTION_STATUS.FIX_FAILED)} failed
        </span>
      </KpiCard>
      <KpiCard
        label="Events · last hour"
        value={events ? events.events.toLocaleString() : "—"}
      >
        <span className="text-text-neutral-tertiary text-xs">
          {events
            ? `${events.changes.toLocaleString()} changes`
            : "Needs the event data store."}
        </span>
      </KpiCard>
    </div>
  );
}
