"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts";

import { formatDateTime } from "@/app/(prowler)/realtime/_lib/display";
import type { RealtimeTimelinePayload } from "@/app/(prowler)/realtime/_types";
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
  marker: "var(--color-bg-data-info)",
} as const;

const CHART_CONFIG: ChartConfig = {
  passed: { label: "Passing checks", color: CHART_COLORS.passed },
  failed: { label: "Failing checks", color: CHART_COLORS.failed },
};

const toTime = (value: string) => new Date(value).getTime();
const formatTick = (value: number) =>
  new Date(value).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });

interface PostureTimelineProps {
  timeline: RealtimeTimelinePayload;
}

/** Checks per scan, with a dashed marker where Realtime acted. */
export function PostureTimeline({ timeline }: PostureTimelineProps) {
  const points = timeline.points
    .map((point) => ({ ...point, time: toTime(point.at) }))
    .filter((point) => !Number.isNaN(point.time))
    .sort((a, b) => a.time - b.time);
  const actionTimes = timeline.actions
    .map((action) => toTime(action.at))
    .filter((time) => !Number.isNaN(time));

  if (points.length === 0) {
    return (
      <p className="text-text-neutral-tertiary flex h-56 items-center justify-center text-sm">
        The chart fills in after the first completed scan of this account.
      </p>
    );
  }

  const times = [...points.map((point) => point.time), ...actionTimes];
  const domain: [number, number] = [Math.min(...times), Math.max(...times)];
  const latest = points[points.length - 1];

  return (
    <>
      <p className="sr-only">
        Posture over {points.length} scans. Latest scan: {latest.passed} passing
        and {latest.failed} failing checks. Prowler Realtime took{" "}
        {actionTimes.length} recorded actions.
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
          {actionTimes.map((time, index) => (
            <ReferenceLine
              key={`${time}-${index}`}
              x={time}
              stroke={CHART_COLORS.marker}
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
    </>
  );
}
