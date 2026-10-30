"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts";

import { ActionStatusBadge } from "@/components/realtime/realtime-badges";
import { PanelEmpty } from "@/components/realtime/realtime-states";
import {
  type ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/shadcn/chart/Chart";
import { formatDateTime, humanize } from "@/lib/realtime/display";
import type { RealtimeTimelinePayload } from "@/types/realtime";

// Recharts props do not take className, so the design tokens go in by name.
const CHART_COLORS = {
  passed: "var(--color-bg-pass)",
  failed: "var(--color-bg-fail)",
  marker: "var(--color-bg-data-info)",
} as const;

const CHART_CONFIG: ChartConfig = {
  passed: { label: "Passing checks", color: CHART_COLORS.passed },
  failed: { label: "Failing checks", color: CHART_COLORS.failed },
};

const MAX_LISTED_ACTIONS = 5;

const toTime = (value: string) => new Date(value).getTime();
const formatTick = (value: number) =>
  new Date(value).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });

/** Posture per scan, with a marker where Prowler Realtime acted. */
export function PostureTimeline({
  timeline,
}: {
  timeline: RealtimeTimelinePayload;
}) {
  const points = timeline.points
    .map((point) => ({ ...point, time: toTime(point.at) }))
    .filter((point) => !Number.isNaN(point.time))
    .sort((a, b) => a.time - b.time);
  const actions = timeline.actions
    .map((action) => ({ ...action, time: toTime(action.at) }))
    .filter((action) => !Number.isNaN(action.time));

  if (points.length === 0) {
    return (
      <div className="flex flex-col gap-3">
        <PanelEmpty
          title="No posture history yet"
          description="The chart fills in after the first completed scan of this account."
        />
        <ActionList actions={actions} title="Prowler Realtime actions" />
      </div>
    );
  }

  const times = [...points, ...actions].map((item) => item.time);
  const domain: [number, number] = [Math.min(...times), Math.max(...times)];
  const latest = points[points.length - 1];

  return (
    <div className="flex flex-col gap-3">
      <p className="sr-only">
        Posture over {points.length} scans. Latest scan: {latest.passed} passing
        and {latest.failed} failing checks. Prowler Realtime took{" "}
        {actions.length} recorded actions.
      </p>
      <ChartContainer
        config={CHART_CONFIG}
        className="aspect-auto h-64 w-full"
        aria-hidden="true"
      >
        <LineChart data={points} margin={{ left: 4, right: 12, top: 8 }}>
          <CartesianGrid vertical={false} />
          <XAxis
            dataKey="time"
            type="number"
            scale="time"
            domain={domain}
            tickFormatter={formatTick}
            tickLine={false}
            axisLine={false}
          />
          <YAxis tickLine={false} axisLine={false} width={40} />
          <ChartTooltip
            content={
              <ChartTooltipContent
                labelFormatter={(_, payload) =>
                  formatDateTime(payload?.[0]?.payload?.at)
                }
              />
            }
          />
          <Line
            dataKey="passed"
            type="monotone"
            stroke={CHART_COLORS.passed}
            strokeWidth={2}
            dot={false}
          />
          <Line
            dataKey="failed"
            type="monotone"
            stroke={CHART_COLORS.failed}
            strokeWidth={2}
            dot={false}
          />
          {actions.map((action, index) => (
            <ReferenceLine
              key={`${action.at}-${index}`}
              x={action.time}
              stroke={CHART_COLORS.marker}
              strokeDasharray="3 3"
            />
          ))}
        </LineChart>
      </ChartContainer>

      <ActionList
        actions={actions}
        title="Prowler Realtime actions (dashed lines)"
      />
    </div>
  );
}

function ActionList({
  actions,
  title,
}: {
  actions: RealtimeTimelinePayload["actions"];
  title: string;
}) {
  if (actions.length === 0) return null;
  return (
    <div className="flex flex-col gap-1">
      <h4 className="text-text-neutral-primary text-sm font-medium">{title}</h4>
      <ul className="flex flex-col gap-1">
        {actions.slice(0, MAX_LISTED_ACTIONS).map((action, index) => (
          <li
            key={`${action.at}-${index}`}
            className="text-text-neutral-secondary flex flex-wrap items-center gap-2 text-sm"
          >
            <span className="text-text-neutral-tertiary tabular-nums">
              {formatDateTime(action.at)}
            </span>
            <ActionStatusBadge status={action.status} />
            <span>{action.summary || humanize(action.kind)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
