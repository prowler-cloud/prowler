"use client";

import { Bell, BellOff, ShieldCheck, TriangleAlert } from "lucide-react";

import { DonutChart } from "@/components/graphs/donut-chart";
import { DonutDataPoint } from "@/components/graphs/types";
import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
  ResourceStatsCard,
  StatsContainer,
} from "@/components/shadcn";
import { CardVariant } from "@/components/shadcn/card/resource-stats-card/resource-stats-card-content";

interface CheckFindingsProps {
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

export const CheckFindings = ({
  failFindingsData,
  passFindingsData,
}: CheckFindingsProps) => {
  // Calculate total findings
  const totalFindings = failFindingsData.total + passFindingsData.total;

  // Calculate percentages
  const failPercentage = Math.round(
    (failFindingsData.total / totalFindings) * 100,
  );
  const passPercentage = Math.round(
    (passFindingsData.total / totalFindings) * 100,
  );

  // Calculate change percentages (new findings as percentage change)
  const failChange =
    failFindingsData.total > 0
      ? Math.round((failFindingsData.new / failFindingsData.total) * 100)
      : 0;
  const passChange =
    passFindingsData.total > 0
      ? Math.round((passFindingsData.new / passFindingsData.total) * 100)
      : 0;

  // Mock data for DonutChart
  const donutData: DonutDataPoint[] = [
    {
      name: "Fail Findings",
      value: failFindingsData.total,
      color: "#f43f5e", // Rose-500
      percentage: Number(failPercentage),
      change: Number(failChange),
    },
    {
      name: "Pass Findings",
      value: passFindingsData.total,
      color: "#4ade80", // Green-400
      percentage: Number(passPercentage),
      change: Number(passChange),
    },
  ];

  return (
    <BaseCard>
      {/* Header */}
      <CardHeader>
        <CardTitle>Check Findings</CardTitle>
      </CardHeader>

      {/* DonutChart Content */}
      <CardContent className="space-y-4">
        <div className="mx-auto max-h-[200px] max-w-[200px]">
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

        {/* Footer with ResourceStatsCards */}
        <StatsContainer className="flex w-full flex-col items-center justify-center gap-4 md:w-[480px] md:flex-row md:items-start md:justify-between">
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
            className="flex-1"
          />

          <div className="flex w-full items-center justify-center md:w-auto md:self-stretch md:px-[46px]">
            <div className="h-px w-full bg-slate-300 md:h-full md:w-px dark:bg-[rgba(39,39,42,1)]" />
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
            className="flex-1"
          />
        </StatsContainer>
      </CardContent>
    </BaseCard>
  );
};
