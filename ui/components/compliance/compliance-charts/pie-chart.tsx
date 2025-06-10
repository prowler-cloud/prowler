"use client";

import { useTheme } from "next-themes";
import {
  Cell,
  Label,
  Pie,
  PieChart as RechartsPieChart,
  Tooltip,
} from "recharts";

import { ChartConfig, ChartContainer } from "@/components/ui/chart/Chart";

interface PieChartProps {
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

export const PieChart = ({ pass, fail, manual }: PieChartProps) => {
  const { theme } = useTheme();

  const chartData = [
    {
      name: "Pass",
      value: pass,
      fill: "#3CEC6D",
    },
    {
      name: "Fail",
      value: fail,
      fill: "#FB718F",
    },
    {
      name: "Manual",
      value: manual,
      fill: "#868994",
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

  interface CustomTooltipProps {
    active: boolean;
    payload: {
      payload: {
        name: string;
        value: number;
        fill: string;
      };
    }[];
  }

  const CustomTooltip = ({ active, payload }: CustomTooltipProps) => {
    if (active && payload && payload.length) {
      const data = payload[0];
      return (
        <div
          style={{
            backgroundColor: theme === "dark" ? "#1e293b" : "white",
            border: `1px solid ${theme === "dark" ? "#475569" : "rgba(0, 0, 0, 0.1)"}`,
            borderRadius: "6px",
            boxShadow: "0px 4px 12px rgba(0, 0, 0, 0.15)",
            fontSize: "12px",
            padding: "8px 12px",
            color: theme === "dark" ? "white" : "black",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <div
              style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                backgroundColor: data.payload.fill,
              }}
            />
            <span>
              {data.payload.name}: {data.payload.value}
            </span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="flex h-[320px] flex-col items-center justify-between">
      <h3 className="whitespace-nowrap text-xs font-semibold uppercase tracking-wide">
        Requirements Status
      </h3>

      <ChartContainer
        config={chartConfig}
        className="aspect-square w-[200px] min-w-[200px]"
      >
        <RechartsPieChart>
          <Tooltip
            cursor={false}
            content={<CustomTooltip active={false} payload={[]} />}
          />
          <Pie
            data={totalRequirements > 0 ? chartData : emptyChartData}
            dataKey="value"
            nameKey="name"
            innerRadius={70}
            outerRadius={100}
            paddingAngle={2}
            cornerRadius={4}
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
        </RechartsPieChart>
      </ChartContainer>

      <div className="mt-2 grid grid-cols-3 gap-4">
        <div className="flex flex-col items-center">
          <div className="text-muted-foreground text-sm">Pass</div>
          <div className="font-semibold text-system-success-medium">{pass}</div>
        </div>
        <div className="flex flex-col items-center">
          <div className="text-muted-foreground text-sm">Fail</div>
          <div className="font-semibold text-system-error-medium">{fail}</div>
        </div>
        <div className="flex flex-col items-center">
          <div className="text-muted-foreground text-sm">Manual</div>
          <div className="font-semibold text-prowler-grey-light">{manual}</div>
        </div>
      </div>
    </div>
  );
};
