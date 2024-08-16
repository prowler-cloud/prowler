"use client";

import { TrendingUp } from "lucide-react";
import * as React from "react";
import { Label, Pie, PieChart } from "recharts";

import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "../ui";

const chartData = [
  { findings: "Success", number: 436, fill: "var(--color-success)" },
  { findings: "Fail", number: 293, fill: "var(--color-fail)" },
];

const chartConfig = {
  number: {
    label: "Findings",
  },
  chrome: {
    label: "Chrome",
    color: "hsl(var(--chart-1))",
  },
  success: {
    label: "Success",
    color: "hsl(var(--chart-success))",
  },
  firefox: {
    label: "Firefox",
    color: "hsl(var(--chart-3))",
  },
  edge: {
    label: "Edge",
    color: "hsl(var(--chart-4))",
  },
  fail: {
    label: "Fail",
    color: "hsl(var(--chart-fail))",
  },
} satisfies ChartConfig;

export function StatusChart() {
  const totalVisitors = React.useMemo(() => {
    return chartData.reduce((acc, curr) => acc + curr.number, 0);
  }, []);

  return (
    <div className="flex">
      <ChartContainer
        config={chartConfig}
        className="mx-auto aspect-square min-h-[250px]"
      >
        <PieChart>
          <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
          <Pie
            data={chartData}
            dataKey="number"
            nameKey="findings"
            innerRadius={60}
            strokeWidth={5}
          >
            <Label
              content={({ viewBox }) => {
                if (viewBox && "cx" in viewBox && "cy" in viewBox) {
                  return (
                    <text
                      x={viewBox.cx}
                      y={viewBox.cy}
                      textAnchor="middle"
                      dominantBaseline="middle"
                    >
                      <tspan
                        x={viewBox.cx}
                        y={viewBox.cy}
                        className="fill-foreground text-3xl font-bold"
                      >
                        {totalVisitors.toLocaleString()}
                      </tspan>
                      <tspan
                        x={viewBox.cx}
                        y={(viewBox.cy || 0) + 24}
                        className="fill-foreground"
                      >
                        Findings
                      </tspan>
                    </text>
                  );
                }
              }}
            />
          </Pie>
        </PieChart>
      </ChartContainer>
      <div className="flex flex-col justify-center gap-y-4 mx-6">
        <div className="flex items-center font-medium leading-none gap-4">
          No change from last scan
        </div>
        <div className="flex items-center gap-2 leading-none text-muted-foreground">
          +2 findings from last scan <TrendingUp className="h-4 w-4" />
        </div>
      </div>
    </div>
  );
}
