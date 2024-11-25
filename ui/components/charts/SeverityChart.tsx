"use client";

import { Bar, BarChart, LabelList, XAxis, YAxis } from "recharts";

import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart/Chart";

const chartData = [
  { severity: "critical", findings: 32, fill: "var(--color-critical)" },
  { severity: "high", findings: 78, fill: "var(--color-high)" },
  { severity: "medium", findings: 117, fill: "var(--color-medium)" },
  { severity: "low", findings: 39, fill: "var(--color-low)" },
];

const chartConfig = {
  findings: {
    label: "Findings",
  },
  critical: {
    label: "Critical",
    color: "hsl(var(--chart-critical))",
  },
  high: {
    label: "High",
    color: "hsl(var(--chart-fail))",
  },
  medium: {
    label: "Medium",
    color: "hsl(var(--chart-medium))",
  },
  low: {
    label: "Low",
    color: "hsl(var(--chart-low))",
  },
} satisfies ChartConfig;

export const SeverityChart = () => {
  return (
    <div className="my-auto">
      <ChartContainer config={chartConfig}>
        <BarChart accessibilityLayer data={chartData} layout="vertical">
          <YAxis
            dataKey="severity"
            type="category"
            tickLine={false}
            tickMargin={10}
            axisLine={false}
            tickFormatter={(value) =>
              chartConfig[value as keyof typeof chartConfig]?.label
            }
          />
          <XAxis dataKey="findings" type="number" hide>
            <LabelList position="insideTop" offset={12} fontSize={12} />
          </XAxis>
          <ChartTooltip
            cursor={false}
            content={<ChartTooltipContent indicator="line" />}
          />

          <Bar dataKey="findings" layout="vertical" radius={12}>
            <LabelList
              position="insideRight"
              offset={10}
              className="fill-foreground font-bold"
              fontSize={12}
            />
          </Bar>
        </BarChart>
      </ChartContainer>
    </div>
  );
};
