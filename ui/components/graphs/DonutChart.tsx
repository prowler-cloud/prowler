"use client";

import { useState } from "react";
import { Cell, Label, Pie, PieChart, Tooltip } from "recharts";

import { ChartConfig, ChartContainer } from "@/components/ui/chart/Chart";

import { ChartLegend } from "./shared/ChartLegend";
import { DonutDataPoint } from "./types";

interface DonutChartProps {
  data: DonutDataPoint[];
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
  showLegend?: boolean;
  centerLabel?: {
    value: string | number;
    label: string;
  };
}

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="rounded-lg border border-slate-700 bg-slate-800 p-3 shadow-lg">
        <div className="flex items-center gap-2">
          <div
            className="h-3 w-3 rounded-sm"
            style={{ backgroundColor: data.color }}
          />
          <span className="text-sm font-semibold text-white">
            {data.percentage}% {data.name}
          </span>
        </div>
        {data.change !== undefined && (
          <p className="mt-2 text-xs text-slate-400">
            <span className="font-bold">
              {data.change > 0 ? "+" : ""}
              {data.change}%
            </span>{" "}
            Since last scan
          </p>
        )}
      </div>
    );
  }
  return null;
};

const CustomLegend = ({ payload }: any) => {
  const items = payload.map((entry: any) => ({
    label: `${entry.value} (${entry.payload.percentage}%)`,
    color: entry.color,
  }));

  return <ChartLegend items={items} />;
};

export function DonutChart({
  data,
  innerRadius = 80,
  outerRadius = 120,
  showLegend = true,
  centerLabel,
}: DonutChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const chartConfig = data.reduce(
    (config, item) => ({
      ...config,
      [item.name]: {
        label: item.name,
        color: item.color,
      },
    }),
    {} as ChartConfig,
  );

  const chartData = data.map((item) => ({
    name: item.name,
    value: item.value,
    fill: item.color,
    color: item.color,
    percentage: item.percentage,
    change: item.change,
  }));

  const legendPayload = chartData.map((entry) => ({
    value: entry.name,
    color: entry.color,
    payload: {
      percentage: entry.percentage,
    },
  }));

  return (
    <div>
      <ChartContainer
        config={chartConfig}
        className="mx-auto aspect-square max-h-[350px]"
      >
        <PieChart>
          <Tooltip content={<CustomTooltip />} />
          <Pie
            data={chartData}
            dataKey="value"
            nameKey="name"
            innerRadius={innerRadius}
            outerRadius={outerRadius}
            strokeWidth={0}
            paddingAngle={2}
          >
            {chartData.map((entry, index) => {
              const opacity =
                hoveredIndex === null ? 1 : hoveredIndex === index ? 1 : 0.5;
              return (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.fill}
                  opacity={opacity}
                  style={{ transition: "opacity 0.2s" }}
                  onMouseEnter={() => setHoveredIndex(index)}
                  onMouseLeave={() => setHoveredIndex(null)}
                />
              );
            })}
            {centerLabel && (
              <Label
                content={({ viewBox }) => {
                  if (viewBox && "cx" in viewBox && "cy" in viewBox) {
                    const formattedValue =
                      typeof centerLabel.value === "number"
                        ? centerLabel.value.toLocaleString()
                        : centerLabel.value;

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
                          className="fill-white text-3xl font-bold"
                        >
                          {formattedValue}
                        </tspan>
                        <tspan
                          x={viewBox.cx}
                          y={(viewBox.cy || 0) + 24}
                          className="fill-slate-400"
                        >
                          {centerLabel.label}
                        </tspan>
                      </text>
                    );
                  }
                }}
              />
            )}
          </Pie>
        </PieChart>
      </ChartContainer>
      {showLegend && <CustomLegend payload={legendPayload} />}
    </div>
  );
}
