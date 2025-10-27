"use client";

import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { BarDataPoint } from "@/components/graphs/types";
import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";

interface RiskSeverityChartProps {
  severityData: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
}

export const RiskSeverityChart = ({ severityData }: RiskSeverityChartProps) => {
  // Calculate total findings
  const totalFindings =
    severityData.critical +
    severityData.high +
    severityData.medium +
    severityData.low +
    severityData.informational;

  // Transform data to BarDataPoint format
  const chartData: BarDataPoint[] = [
    {
      name: "Critical",
      value: severityData.critical,
      percentage: Math.round((severityData.critical / totalFindings) * 100),
    },
    {
      name: "High",
      value: severityData.high,
      percentage: Math.round((severityData.high / totalFindings) * 100),
    },
    {
      name: "Medium",
      value: severityData.medium,
      percentage: Math.round((severityData.medium / totalFindings) * 100),
    },
    {
      name: "Low",
      value: severityData.low,
      percentage: Math.round((severityData.low / totalFindings) * 100),
    },
    {
      name: "Info",
      value: severityData.informational,
      percentage: Math.round(
        (severityData.informational / totalFindings) * 100,
      ),
    },
  ];

  return (
    <BaseCard className="flex h-full flex-col">
      <CardHeader>
        <CardTitle>Risk Severity</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-1 items-center justify-start px-6">
        <HorizontalBarChart data={chartData} />
      </CardContent>
    </BaseCard>
  );
};
