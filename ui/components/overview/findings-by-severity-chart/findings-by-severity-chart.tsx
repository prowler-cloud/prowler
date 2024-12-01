"use client";

import { Card, CardBody } from "@nextui-org/react";
import { Bar, BarChart, LabelList, XAxis, YAxis } from "recharts";

import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart/Chart";
import { FindingsSeverityOverview } from "@/types/components";

const chartConfig = {
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
  informational: {
    label: "Informational",
    color: "hsl(var(--chart-informational))",
  },
} satisfies ChartConfig;

export const FindingsBySeverityChart = ({
  findingsBySeverity,
}: {
  findingsBySeverity: FindingsSeverityOverview;
}) => {
  const defaultAttributes = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };

  const attributes = findingsBySeverity?.data?.attributes || defaultAttributes;

  const chartData = Object.entries(attributes).map(([severity, findings]) => ({
    severity,
    findings,
    fill: chartConfig[severity as keyof typeof chartConfig]?.color,
  }));

  return (
    <Card className="h-full dark:bg-prowler-blue-400">
      <CardBody>
        <div className="my-auto">
          <ChartContainer config={chartConfig}>
            <BarChart
              accessibilityLayer
              data={chartData}
              layout="vertical"
              barGap={2}
              height={200}
              margin={{ left: 50 }}
              width={500}
            >
              <YAxis
                dataKey="severity"
                type="category"
                tickLine={false}
                tickMargin={20}
                axisLine={false}
                tickFormatter={(value) =>
                  chartConfig[value as keyof typeof chartConfig]?.label
                }
              />
              <XAxis dataKey="findings" type="number" hide>
                <LabelList position="insideTop" offset={1} fontSize={12} />
              </XAxis>
              <ChartTooltip
                cursor={false}
                content={<ChartTooltipContent indicator="line" />}
              />
              <Bar
                dataKey="findings"
                layout="vertical"
                radius={12}
                barSize={20}
              >
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
      </CardBody>
    </Card>
  );
};
