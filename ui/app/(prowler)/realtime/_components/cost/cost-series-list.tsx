"use client";

import { Line, LineChart } from "recharts";

import { formatMoney } from "@/app/(prowler)/realtime/_lib/display";
import type { RealtimeCostSeries } from "@/app/(prowler)/realtime/_types";
import { Card } from "@/components/shadcn";
import {
  type ChartConfig,
  ChartContainer,
} from "@/components/shadcn/chart/Chart";

import { COST_CHART_COLORS } from "./anomaly-chart";

const CHART_CONFIG: ChartConfig = {
  amount: { label: "Daily spend", color: COST_CHART_COLORS.spend },
};

interface CostSeriesListProps {
  series: RealtimeCostSeries[];
}

/** The top services by latest spend, each with its last 14 days. */
export function CostSeriesList({ series }: CostSeriesListProps) {
  if (series.length === 0) {
    return (
      <p className="text-text-neutral-tertiary text-sm">
        No daily cost yet. Figures appear after the next Cost Explorer read.
      </p>
    );
  }
  return (
    <Card variant="base" className="gap-0 p-0">
      <ul className="flex flex-col">
        {series.map((item) => (
          <li
            key={`${item.service}|${item.region}`}
            className="border-border-neutral-secondary grid grid-cols-[minmax(0,1fr)_8rem_6rem] items-center gap-4 border-t px-4 py-3 first:border-t-0 sm:grid-cols-[minmax(0,1fr)_12rem_7rem_7rem]"
          >
            <div className="flex min-w-0 flex-col gap-0.5">
              <span className="text-text-neutral-primary truncate text-sm">
                {item.service}
              </span>
              <span className="text-text-neutral-tertiary text-xs">
                {item.region}
              </span>
            </div>
            <ChartContainer
              config={CHART_CONFIG}
              className="aspect-auto h-10 w-full"
              aria-hidden="true"
            >
              <LineChart data={item.days}>
                <Line
                  dataKey="amount"
                  type="monotone"
                  stroke={COST_CHART_COLORS.spend}
                  strokeWidth={1.5}
                  dot={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ChartContainer>
            <div className="flex flex-col text-right">
              <span className="text-text-neutral-primary text-sm font-medium">
                {formatMoney(item.latest)}
              </span>
              <span className="text-text-neutral-tertiary text-xs">latest</span>
            </div>
            <div className="hidden flex-col text-right sm:flex">
              <span className="text-text-neutral-secondary text-sm">
                {formatMoney(item.base)}
              </span>
              <span className="text-text-neutral-tertiary text-xs">
                baseline
              </span>
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}
