"use client";

import { Bell, BellOff, ShieldCheck, TriangleAlert } from "lucide-react";

import { DonutChart } from "@/components/graphs/donut-chart";
import { DonutDataPoint } from "@/components/graphs/types";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardVariant,
  Skeleton,
} from "@/components/shadcn";
import { calculatePercentage } from "@/lib/utils";

import { ResourceStatsCard } from "../resource-stats-card";

interface StatusChartProps {
  failFindingsData: {
    total: number;
    new: number;
    muted: number;
  };
  passFindingsData: {
    total: number;
    new: number;
    muted: number;
  };
}

export const StatusChart = ({
  failFindingsData,
  passFindingsData,
}: StatusChartProps) => {
  // Calculate total findings
  const totalFindings = failFindingsData.total + passFindingsData.total;

  // Calculate percentages
  const failPercentage = calculatePercentage(
    failFindingsData.total,
    totalFindings,
  );
  const passPercentage = calculatePercentage(
    passFindingsData.total,
    totalFindings,
  );

  // Calculate change percentages (new findings as percentage change)
  const failChange = calculatePercentage(
    failFindingsData.new,
    failFindingsData.total,
  );
  const passChange = calculatePercentage(
    passFindingsData.new,
    passFindingsData.total,
  );

  // Mock data for DonutChart
  const donutData: DonutDataPoint[] = [
    {
      name: "Fail Findings",
      value: failFindingsData.total,
      color: "var(--bg-fail-primary)",
      percentage: Number(failPercentage),
      change: Number(failChange),
    },
    {
      name: "Pass Findings",
      value: passFindingsData.total,
      color: "var(--bg-pass-primary)",
      percentage: Number(passPercentage),
      change: Number(passChange),
    },
  ];

  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col justify-between md:min-w-[380px]"
    >
      <CardHeader>
        <CardTitle>Check Findings</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        <div className="mx-auto h-[172px] w-[172px]">
          <DonutChart
            data={donutData}
            showLegend={false}
            innerRadius={66}
            outerRadius={86}
            centerLabel={{
              value: totalFindings.toLocaleString(),
              label: "Total Findings",
            }}
          />
        </div>

        <Card
          variant="inner"
          padding="md"
          className="flex w-full flex-col items-start justify-center gap-4 lg:flex-row lg:justify-between"
        >
          <ResourceStatsCard
            containerless
            badge={{
              icon: TriangleAlert,
              count: failFindingsData.total,
              variant: CardVariant.fail,
            }}
            label="Fail Findings"
            stats={[
              { icon: Bell, label: `${failFindingsData.new} New` },
              { icon: BellOff, label: `${failFindingsData.muted} Muted` },
            ]}
            emptyState={
              failFindingsData.total === 0
                ? { message: "No failed findings to display" }
                : undefined
            }
            className="w-full lg:min-w-0 lg:flex-1"
          />

          <div className="flex w-full items-center justify-center lg:w-auto lg:self-stretch">
            <div className="bg-border-neutral-primary h-px w-full lg:h-full lg:w-px" />
          </div>

          <ResourceStatsCard
            containerless
            badge={{
              icon: ShieldCheck,
              count: passFindingsData.total,
              variant: CardVariant.pass,
            }}
            label="Pass Findings"
            stats={[
              { icon: Bell, label: `${passFindingsData.new} New` },
              { icon: BellOff, label: `${passFindingsData.muted} Muted` },
            ]}
            emptyState={
              passFindingsData.total === 0
                ? { message: "No passed findings to display" }
                : undefined
            }
            className="w-full lg:min-w-0 lg:flex-1"
          />
        </Card>
      </CardContent>
    </Card>
  );
};

export function StatusChartSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col justify-between md:min-w-[380px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-[260px] rounded-xl" />
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        {/* Circular skeleton for donut chart */}
        <div className="mx-auto h-[172px] w-[172px]">
          <Skeleton className="size-[172px] rounded-full" />
        </div>

        {/* Bottom info box skeleton */}
        <Skeleton className="h-[97px] w-full shrink-0 rounded-xl" />
      </CardContent>
    </Card>
  );
}
