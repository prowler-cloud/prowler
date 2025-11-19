"use client";

import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { BarDataPoint } from "@/components/graphs/types";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Skeleton,
} from "@/components/shadcn";
import { calculatePercentage } from "@/lib/utils";

interface RiskSeverityChartProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export const RiskSeverityChart = ({
  critical,
  high,
  medium,
  low,
  informational,
}: RiskSeverityChartProps) => {
  // Calculate total findings
  const totalFindings = critical + high + medium + low + informational;

  // Transform data to BarDataPoint format
  const chartData: BarDataPoint[] = [
    {
      name: "Critical",
      value: critical,
      percentage: calculatePercentage(critical, totalFindings),
    },
    {
      name: "High",
      value: high,
      percentage: calculatePercentage(high, totalFindings),
    },
    {
      name: "Medium",
      value: medium,
      percentage: calculatePercentage(medium, totalFindings),
    },
    {
      name: "Low",
      value: low,
      percentage: calculatePercentage(low, totalFindings),
    },
    {
      name: "Info",
      value: informational,
      percentage: calculatePercentage(informational, totalFindings),
    },
  ];

  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col md:min-w-[380px]"
    >
      <CardHeader>
        <CardTitle>Risk Severity</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-1 items-center justify-start px-6">
        <HorizontalBarChart data={chartData} />
      </CardContent>
    </Card>
  );
};

export function RiskSeverityChartSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col md:min-w-[380px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-[260px] rounded-xl" />
      </CardHeader>

      <CardContent className="flex flex-1 items-center justify-start px-6">
        <div className="flex w-full flex-col gap-6">
          {/* 5 horizontal bar skeletons */}
          {Array.from({ length: 5 }).map((_, index) => (
            <div key={index} className="flex h-7 w-full gap-6">
              <Skeleton className="h-full w-28 shrink-0 rounded-xl" />
              <Skeleton className="h-full flex-1 rounded-xl" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
