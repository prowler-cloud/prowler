"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts";

import { PanelEmpty } from "@/components/realtime/realtime-states";
import {
  type ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/shadcn/chart/Chart";
import { formatMoney } from "@/lib/realtime/display";
import type { RealtimeCostDay, RealtimeCostThresholds } from "@/types/realtime";

// Recharts props do not take className, so the design tokens go in by name.
const CHART_COLORS = {
  spend: "var(--color-bg-data-info)",
  baseline: "var(--color-bg-pass)",
  threshold: "var(--color-bg-fail)",
} as const;

const CHART_CONFIG: ChartConfig = {
  amount: { label: "Daily spend", color: CHART_COLORS.spend },
};

/** Spend at which a day counts as an anomaly: both thresholds must be crossed. */
export const anomalyThreshold = (
  baseline: number,
  thresholds: RealtimeCostThresholds,
): number =>
  Math.max(baseline * thresholds.min_ratio, baseline + thresholds.min_delta);

/** The mean of the days before the last one, when the API gave no baseline. */
export const baselineOf = (series: RealtimeCostDay[]): number => {
  const earlier = series.slice(0, -1);
  if (earlier.length === 0) return 0;
  return earlier.reduce((sum, day) => sum + day.amount, 0) / earlier.length;
};

/** Daily spend of one service with its baseline and the line that makes it an anomaly. */
export function AnomalyChart({
  series,
  baseline,
  thresholds,
  label,
}: {
  series: RealtimeCostDay[];
  baseline: number;
  thresholds: RealtimeCostThresholds;
  label: string;
}) {
  if (series.length === 0) {
    return (
      <PanelEmpty
        title="No daily cost yet"
        description="The chart fills in once Cost Explorer has returned figures for this service."
      />
    );
  }
  const threshold = anomalyThreshold(baseline, thresholds);
  const latest = series[series.length - 1];

  return (
    <div className="flex flex-col gap-3">
      <p className="sr-only">
        {label}. Latest day {latest.day}: {formatMoney(latest.amount)}. Baseline{" "}
        {formatMoney(baseline)}; anomaly threshold {formatMoney(threshold)}.
      </p>
      <ChartContainer
        config={CHART_CONFIG}
        className="aspect-auto h-64 w-full"
        aria-hidden="true"
      >
        <LineChart data={series} margin={{ left: 4, right: 12, top: 8 }}>
          <CartesianGrid vertical={false} />
          <XAxis
            dataKey="day"
            tickLine={false}
            axisLine={false}
            minTickGap={24}
          />
          <YAxis
            tickLine={false}
            axisLine={false}
            width={56}
            tickFormatter={(value: number) => formatMoney(value)}
          />
          <ChartTooltip
            content={
              <ChartTooltipContent
                formatter={(value) => formatMoney(Number(value))}
              />
            }
          />
          <Line
            dataKey="amount"
            type="monotone"
            stroke={CHART_COLORS.spend}
            strokeWidth={2}
            dot={false}
          />
          <ReferenceLine
            y={baseline}
            stroke={CHART_COLORS.baseline}
            strokeDasharray="4 4"
            ifOverflow="extendDomain"
          />
          <ReferenceLine
            y={threshold}
            stroke={CHART_COLORS.threshold}
            strokeDasharray="2 4"
            // Keep the threshold on the chart when every day is below it.
            ifOverflow="extendDomain"
          />
        </LineChart>
      </ChartContainer>
      <ul className="text-text-neutral-secondary flex flex-wrap gap-x-4 gap-y-1 text-xs">
        <li>Solid: daily spend</li>
        <li>Green dashed: baseline ({formatMoney(baseline)})</li>
        <li>Red dotted: anomaly threshold ({formatMoney(threshold)})</li>
      </ul>
    </div>
  );
}
