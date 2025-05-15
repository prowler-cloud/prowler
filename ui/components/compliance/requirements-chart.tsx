"use client";

import { Cell, Label, Pie, PieChart } from "recharts";

import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart/Chart";

interface RequirementsChartProps {
  pass: number;
  fail: number;
  manual: number;
}

const chartConfig = {
  number: {
    label: "Requirements",
  },
  pass: {
    label: "Pass",
    color: "hsl(var(--chart-success))",
  },
  fail: {
    label: "Fail",
    color: "hsl(var(--chart-fail))",
  },
  manual: {
    label: "Manual",
    color: "hsl(var(--chart-warning))",
  },
} satisfies ChartConfig;

export function RequirementsChart({
  pass,
  fail,
  manual,
}: RequirementsChartProps) {
  const chartData = [
    {
      name: "Pass",
      value: pass,
      fill: "#09BF3D",
    },
    {
      name: "Fail",
      value: fail,
      fill: "#E11D48",
    },
    {
      name: "Manual",
      value: manual,
      fill: "#FBBF24",
    },
  ];

  const totalRequirements = pass + fail + manual;

  const emptyChartData = [
    {
      name: "Empty",
      value: 1,
      fill: "#64748b",
    },
  ];

  return (
    <div className="flex h-[400px] flex-col items-center justify-between rounded-lg border-2 border-gray-200 p-4 dark:border-gray-700">
      <h3 className="whitespace-nowrap text-lg font-medium">
        Requirements Status
      </h3>

      <ChartContainer
        config={chartConfig}
        className="aspect-square w-[200px] min-w-[200px]"
      >
        <PieChart>
          <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
          <Pie
            data={totalRequirements > 0 ? chartData : emptyChartData}
            dataKey="value"
            nameKey="name"
            innerRadius={55}
            outerRadius={80}
            paddingAngle={2}
          >
            {(totalRequirements > 0 ? chartData : emptyChartData).map(
              (entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ),
            )}
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
                        className="fill-foreground text-xl font-bold"
                      >
                        {totalRequirements}
                      </tspan>
                      <tspan
                        x={viewBox.cx}
                        y={(viewBox.cy || 0) + 20}
                        className="fill-foreground text-xs"
                      >
                        Total
                      </tspan>
                    </text>
                  );
                }
              }}
            />
          </Pie>
        </PieChart>
      </ChartContainer>

      <div className="mt-2 grid grid-cols-3 gap-4">
        <div className="flex flex-col items-center">
          <div className="text-muted-foreground text-xs">Pass</div>
          <div className="font-semibold text-success">{pass}</div>
        </div>
        <div className="flex flex-col items-center">
          <div className="text-muted-foreground text-xs">Fail</div>
          <div className="font-semibold text-danger">{fail}</div>
        </div>
        <div className="flex flex-col items-center">
          <div className="text-muted-foreground text-xs">Manual</div>
          <div className="font-semibold text-warning">{manual}</div>
        </div>
      </div>
    </div>
  );
}

export default RequirementsChart;
