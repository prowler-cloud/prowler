"use client";

import { Bell, BellOff, ShieldCheck, TriangleAlert } from "lucide-react";

import { DonutChart } from "@/components/graphs/DonutChart";
import { DonutDataPoint } from "@/components/graphs/types";
import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
  ResourceStatsCard,
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
  const failPercentage = (
    (failFindingsData.total / totalFindings) *
    100
  ).toFixed(1);
  const passPercentage = (
    (passFindingsData.total / totalFindings) *
    100
  ).toFixed(1);

  // Mock data for DonutChart
  const donutData: DonutDataPoint[] = [
    {
      name: "Fail Findings",
      value: failFindingsData.total,
      color: "#f43f5e", // Rose-500
      percentage: Number(failPercentage),
    },
    {
      name: "Pass Findings",
      value: passFindingsData.total,
      color: "#4ade80", // Green-400
      percentage: Number(passPercentage),
    },
  ];

  return (
    <BaseCard>
      {/* Header */}
      <CardHeader>
        <CardTitle>Check Findings</CardTitle>
      </CardHeader>

      {/* DonutChart Content */}
      <CardContent>
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
      </CardContent>

      {/* Footer with ResourceStatsCards */}
      <div className="flex rounded-xl border border-[rgba(38,38,38,0.7)] bg-[rgba(23,23,23,0.5)] px-[19px] py-[9px] backdrop-blur-[46px]">
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
          className="flex-1"
        />

        <div className="flex items-center justify-center px-[46px]">
          <div
            className="h-full w-px"
            style={{ backgroundColor: "rgba(39, 39, 42, 1)" }}
          />
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
          className="flex-1"
        />
      </div>
    </BaseCard>
  );
};
