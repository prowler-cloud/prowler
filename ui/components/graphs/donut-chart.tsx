"use client";

import { useState } from "react";
import { Cell, Label, Pie, PieChart, Tooltip } from "recharts";

import { ChartConfig, ChartContainer } from "@/components/ui/chart/Chart";

import { ChartLegend } from "./shared/chart-legend";
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
  if (!active || !payload || !payload.length) return null;

  const entry = payload[0];
  const name = entry.name;
  const percentage = entry.payload?.percentage;
  const color = entry.color || entry.payload?.color;
  const change = entry.payload?.change;

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-lg dark:border-slate-600 dark:bg-slate-800">
      <div className="flex items-center gap-1">
        <div
          className="h-3 w-3 rounded-sm"
          style={{ backgroundColor: color }}
        />
        <span className="text-sm font-semibold text-slate-600 dark:text-zinc-300">
          {percentage}%
        </span>
        <span>{name}</span>
      </div>
      <p className="mt-1 text-xs text-slate-600 dark:text-zinc-300">
        {change !== undefined && (
          <>
            <span className="font-bold">
              {change > 0 ? "+" : ""}
              {change}%
            </span>
            <span> Since Last Scan</span>
          </>
        )}
      </p>
    </div>
  );
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
  innerRadius = 68,
  outerRadius = 86,
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
    <>
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
            paddingAngle={0}
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
                          className="text-3xl font-bold text-black dark:text-white"
                          style={{
                            fill: "currentColor",
                          }}
                        >
                          {formattedValue}
                        </tspan>
                        <tspan
                          x={viewBox.cx}
                          y={(viewBox.cy || 0) + 24}
                          className="text-black dark:text-white"
                          style={{
                            fill: "currentColor",
                          }}
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
    </>
  );
}
