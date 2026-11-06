"use client";

import Link from "next/link";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts";

import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import {
  actionStatusBadge,
  formatDateTime,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  REALTIME_TAB,
  realtimeHref,
} from "@/app/(prowler)/realtime/_lib/routes";
import {
  countTimelineGroups,
  latestTimelineActions,
  TIMELINE_GROUP,
  TIMELINE_GROUP_LABELS,
  type TimelineGroup,
  timelineGroup,
} from "@/app/(prowler)/realtime/_lib/timeline";
import type { RealtimeTimelinePayload } from "@/app/(prowler)/realtime/_types";
import { Button } from "@/components/shadcn";
import {
  type ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/shadcn/chart/Chart";

// Recharts props do not take className, so the design tokens go in by name.
const CHART_COLORS = {
  passed: "var(--color-bg-pass)",
  failed: "var(--color-bg-fail)",
} as const;

const GROUP_COLORS: Record<TimelineGroup, string> = {
  [TIMELINE_GROUP.FIXED]: "var(--color-bg-data-info)",
  [TIMELINE_GROUP.CODE]: "var(--color-bg-data-medium)",
  [TIMELINE_GROUP.DRY_RUN]: "var(--color-bg-data-muted)",
  [TIMELINE_GROUP.FAILED]: "var(--color-bg-data-critical)",
  [TIMELINE_GROUP.OTHER]: "var(--color-bg-data-muted)",
};

const CHART_CONFIG: ChartConfig = {
  passed: { label: "Passing checks", color: CHART_COLORS.passed },
  failed: { label: "Failing checks", color: CHART_COLORS.failed },
};

const LATEST_ACTIONS = 4;

const toTime = (value: string) => new Date(value).getTime();
const formatTick = (value: number) =>
  new Date(value).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });

interface LegendItemProps {
  color: string;
  label: string;
  dashed?: boolean;
}

function LegendItem({ color, label, dashed = false }: LegendItemProps) {
  return (
    <li className="flex items-center gap-1.5">
      <span
        aria-hidden
        className="h-0 w-4 border-t-2"
        style={{ borderColor: color, borderStyle: dashed ? "dashed" : "solid" }}
      />
      {label}
    </li>
  );
}

interface PostureTimelineProps {
  providerId: string;
  timeline: RealtimeTimelinePayload;
}

/** Checks per scan, with each Realtime action marked by what it did. */
export function PostureTimeline({
  providerId,
  timeline,
}: PostureTimelineProps) {
  const points = timeline.points
    .map((point) => ({ ...point, time: toTime(point.at) }))
    .filter((point) => !Number.isNaN(point.time))
    .sort((a, b) => a.time - b.time);
  const actions = timeline.actions.filter(
    (action) => !Number.isNaN(toTime(action.at)),
  );

  if (points.length === 0) {
    return (
      <p className="text-text-neutral-tertiary flex h-56 items-center justify-center text-sm">
        The chart fills in after the first completed scan of this account.
      </p>
    );
  }

  const times = [
    ...points.map((point) => point.time),
    ...actions.map((action) => toTime(action.at)),
  ];
  const domain: [number, number] = [Math.min(...times), Math.max(...times)];
  const latest = points[points.length - 1];
  const groups = countTimelineGroups(actions);
  const recent = latestTimelineActions(actions, LATEST_ACTIONS);

  return (
    <div className="flex flex-col gap-3">
      <p className="sr-only">
        Posture over {points.length} scans. Latest scan: {latest.passed} passing
        and {latest.failed} failing checks. Prowler Realtime took{" "}
        {actions.length} recorded actions.
      </p>
      <ChartContainer
        config={CHART_CONFIG}
        className="aspect-auto h-56 w-full"
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
          {actions.map((action, index) => (
            <ReferenceLine
              key={`${action.at}-${index}`}
              x={toTime(action.at)}
              stroke={GROUP_COLORS[timelineGroup(action.status)]}
              strokeDasharray="4 4"
            />
          ))}
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
        </LineChart>
      </ChartContainer>

      <ul
        aria-label="Chart legend"
        className="text-text-neutral-secondary flex flex-wrap gap-x-4 gap-y-1 text-xs"
      >
        <LegendItem color={CHART_COLORS.passed} label="Passing checks" />
        <LegendItem color={CHART_COLORS.failed} label="Failing checks" />
        {groups.map(({ group, count }) => (
          <LegendItem
            key={group}
            color={GROUP_COLORS[group]}
            label={`${TIMELINE_GROUP_LABELS[group]} · ${count}`}
            dashed
          />
        ))}
      </ul>

      <div className="border-border-neutral-secondary flex flex-col gap-2 border-t pt-3">
        <div className="flex items-center justify-between gap-3">
          <h4 className="text-text-neutral-primary text-sm font-medium">
            Latest Realtime actions
          </h4>
          {recent.length > 0 && (
            <Button variant="link" size="link-sm" asChild>
              <Link href={realtimeHref(providerId, REALTIME_TAB.REMEDIATION)}>
                View all actions
              </Link>
            </Button>
          )}
        </div>
        {recent.length === 0 ? (
          <p className="text-text-neutral-tertiary text-sm">
            Prowler Realtime has not fixed or proposed anything in this account
            yet.
          </p>
        ) : (
          <ul className="flex flex-col">
            {recent.map((action, index) => (
              <li
                key={`${action.at}-${index}`}
                className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1 py-1.5"
              >
                <span className="text-text-neutral-primary line-clamp-2 text-sm">
                  {action.summary}
                </span>
                <RealtimeBadge descriptor={actionStatusBadge(action.status)} />
                <span className="text-text-neutral-tertiary text-xs">
                  {formatDateTime(action.at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
