"use client";

import { Card, CardBody } from "@heroui/card";
import { Bar, BarChart, LabelList, XAxis, YAxis } from "recharts";

import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart/Chart";
import { FindingsSeverityOverview } from "@/types/components";

export interface ChartConfig {
  [key: string]: {
    label?: React.ReactNode;
    icon?: React.ComponentType<object>;
    color?: string;
    theme?: string;
    link?: string;
  };
}

const chartConfig = {
  critical: {
    label: "Critical",
    color: "var(--color-bg-data-critical)",
    link: "/findings?filter%5Bstatus__in%5D=FAIL&filter%5Bseverity__in%5D=critical",
  },
  high: {
    label: "High",
    color: "var(--color-bg-data-high)",
    link: "/findings?filter%5Bstatus__in%5D=FAIL&filter%5Bseverity__in%5D=high",
  },
  medium: {
    label: "Medium",
    color: "var(--color-bg-data-medium)",
    link: "/findings?filter%5Bstatus__in%5D=FAIL&filter%5Bseverity__in%5D=medium",
  },
  low: {
    label: "Low",
    color: "var(--color-bg-data-low)",
    link: "/findings?filter%5Bstatus__in%5D=FAIL&filter%5Bseverity__in%5D=low",
  },
  informational: {
    label: "Informational",
    color: "var(--color-bg-data-info)",
    link: "/findings?filter%5Bstatus__in%5D=FAIL&filter%5Bseverity__in%5D=informational",
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
    <Card className="dark:bg-prowler-blue-400 h-full">
      <CardBody>
        <div className="my-auto">
          <ChartContainer
            config={chartConfig}
            className="aspect-auto h-[450px] w-full"
          >
            <BarChart
              accessibilityLayer
              data={chartData}
              layout="vertical"
              margin={{ left: 72, right: 16, top: 8, bottom: 8 }}
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
                barSize={26}
                onClick={(data) => {
                  const severity = data.severity as keyof typeof chartConfig;
                  const link = chartConfig[severity]?.link;
                  if (link) {
                    window.location.href = link;
                  }
                }}
                style={{ cursor: "pointer" }}
              >
                <LabelList
                  position="insideRight"
                  offset={5}
                  className="fill-foreground font-bold"
                  fontSize={11}
                  formatter={(value: number) => (value === 0 ? "" : value)}
                />
                <LabelList
                  position="insideLeft"
                  offset={6}
                  className="fill-foreground font-bold"
                  fontSize={11}
                  formatter={(value: number) => (value === 0 ? "0" : "")}
                />
              </Bar>
            </BarChart>
          </ChartContainer>
        </div>
      </CardBody>
    </Card>
  );
};
