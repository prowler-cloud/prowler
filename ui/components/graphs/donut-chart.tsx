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

  const total = chartData.reduce((sum, d) => sum + (Number(d.value) || 0), 0);
  const isEmpty = total <= 0;

  const emptyData = [
    {
      name: "No data",
      value: 1,
      fill: "var(--chart-border-emphasis)",
      color: "var(--chart-border-emphasis)",
      percentage: 0,
      change: undefined,
    },
  ];

  const legendPayload = (isEmpty ? emptyData : chartData).map((entry) => ({
    value: isEmpty ? "No data" : entry.name,
    color: entry.color,
    payload: {
      percentage: isEmpty ? 0 : entry.percentage,
    },
  }));

  return (
    <>
      <ChartContainer
        config={chartConfig}
        className="mx-auto aspect-square max-h-[350px]"
      >
        <PieChart>
          {!isEmpty && <Tooltip content={<CustomTooltip />} />}
          <Pie
            data={isEmpty ? emptyData : chartData}
            dataKey="value"
            nameKey="name"
            innerRadius={innerRadius}
            outerRadius={outerRadius}
            strokeWidth={0}
            paddingAngle={0}
          >
            {(isEmpty ? emptyData : chartData).map((entry, index) => {
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
            {(centerLabel || isEmpty) && (
              <Label
                content={({ viewBox }) => {
                  if (viewBox && "cx" in viewBox && "cy" in viewBox) {
                    const centerValue = centerLabel ? centerLabel.value : 0;
                    const centerText = centerLabel
                      ? centerLabel.label
                      : "No data";
                    const formattedValue =
                      typeof centerValue === "number"
                        ? centerValue.toLocaleString()
                        : centerValue;

                    return (
                      <text
                        x={viewBox.cx}
                        y={viewBox.cy}
                        textAnchor="middle"
                        dominantBaseline="middle"
                      >
                        <tspan
                          x={viewBox.cx}
                          y={(viewBox.cy || 0) - 6}
                          className="text-2xl font-bold text-zinc-800 dark:text-zinc-300"
                          style={{
                            fill: "currentColor",
                          }}
                        >
                          {formattedValue}
                        </tspan>
                        <tspan
                          x={viewBox.cx}
                          y={(viewBox.cy || 0) + 24}
                          className="text-xs text-zinc-800 dark:text-zinc-400"
                          style={{
                            fill: "currentColor",
                          }}
                        >
                          {centerText}
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
