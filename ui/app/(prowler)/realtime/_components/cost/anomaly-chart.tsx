"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts";

import { formatMoney } from "@/app/(prowler)/realtime/_lib/display";
import type {
  RealtimeCostDay,
  RealtimeCostThresholds,
} from "@/app/(prowler)/realtime/_types";
import {
  type ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/shadcn/chart/Chart";

// Recharts props do not take className, so the design tokens go in by name.
export const COST_CHART_COLORS = {
  spend: "var(--color-bg-data-info)",
  baseline: "var(--color-bg-pass)",
  threshold: "var(--color-bg-fail)",
} as const;

const CHART_CONFIG: ChartConfig = {
  amount: { label: "Daily spend", color: COST_CHART_COLORS.spend },
};

/** Spend at which a day counts as an anomaly: both thresholds must be crossed. */
const anomalyThreshold = (
  baseline: number,
  thresholds: RealtimeCostThresholds,
): number =>
  Math.max(baseline * thresholds.min_ratio, baseline + thresholds.min_delta);

/** The mean of the days before the last one. */
export const baselineOf = (series: RealtimeCostDay[]): number => {
  const earlier = series.slice(0, -1);
  if (earlier.length === 0) return 0;
  return earlier.reduce((sum, day) => sum + day.amount, 0) / earlier.length;
};

interface AnomalyChartProps {
  series: RealtimeCostDay[];
  baseline: number;
  thresholds: RealtimeCostThresholds;
  label: string;
}

/** Daily spend of one service, its baseline and the line that makes it an anomaly. */
export function AnomalyChart({
  series,
  baseline,
  thresholds,
  label,
}: AnomalyChartProps) {
  if (series.length === 0) {
    return (
      <p className="text-text-neutral-tertiary text-sm">
        No daily cost yet. The chart fills in once Cost Explorer returns figures
        for this service.
      </p>
    );
  }
  const threshold = anomalyThreshold(baseline, thresholds);
  const latest = series[series.length - 1];

  return (
    <div className="flex flex-col gap-2">
      <p className="sr-only">
        {label}. Latest day {latest.day}: {formatMoney(latest.amount)}. Baseline{" "}
        {formatMoney(baseline)}; anomaly threshold {formatMoney(threshold)}.
      </p>
      <ChartContainer
        config={CHART_CONFIG}
        className="aspect-auto h-56 w-full"
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
            width={64}
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
            stroke={COST_CHART_COLORS.spend}
            strokeWidth={2}
            dot={false}
          />
          <ReferenceLine
            y={baseline}
            stroke={COST_CHART_COLORS.baseline}
            strokeDasharray="4 4"
            ifOverflow="extendDomain"
          />
          <ReferenceLine
            y={threshold}
            stroke={COST_CHART_COLORS.threshold}
            strokeDasharray="2 4"
            ifOverflow="extendDomain"
          />
        </LineChart>
      </ChartContainer>
      <ul className="text-text-neutral-tertiary flex flex-wrap gap-x-4 gap-y-1 text-xs">
        <li>Solid: daily spend</li>
        <li>Dashed: baseline ({formatMoney(baseline)})</li>
        <li>Dotted: anomaly threshold ({formatMoney(threshold)})</li>
      </ul>
    </div>
  );
}
