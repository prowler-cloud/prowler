"use client";

import { useState } from "react";
import { Cell, Label, Pie, PieChart, Sector, Tooltip } from "recharts";

import { ChartConfig, ChartContainer } from "@/components/ui/chart/Chart";

import { ChartLegend } from "./shared/chart-legend";
import { DonutDataPoint } from "./types";

const CHART_COLORS = {
  emptyState: "var(--border-neutral-tertiary)",
};

interface TooltipPayloadData {
  percentage?: number;
  change?: number;
  color?: string;
}

interface TooltipPayloadEntry {
  name: string;
  color?: string;
  payload?: TooltipPayloadData;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
}

interface LegendPayloadData {
  percentage?: number;
}

interface LegendPayloadEntry {
  value: string;
  color: string;
  payload: LegendPayloadData;
}

interface CustomLegendProps {
  payload: LegendPayloadEntry[];
}

interface CenterLabel {
  value: string | number;
  label: string;
}

interface DonutChartProps {
  data: DonutDataPoint[];
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
  showLegend?: boolean;
  centerLabel?: CenterLabel;
  onSegmentClick?: (dataPoint: DonutDataPoint, index: number) => void;
}

const CustomTooltip = ({ active, payload }: CustomTooltipProps) => {
  if (!active || !payload || !payload.length) return null;

  const entry = payload[0];
  const name = entry.name;
  const percentage = entry.payload?.percentage;
  const color = entry.color || entry.payload?.color;
  const change = entry.payload?.change;

  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary rounded-xl border px-3 py-1.5 shadow-lg">
      <div className="flex flex-col gap-0.5">
        {/* Title with color chip */}
        <div className="flex items-center gap-1">
          <div
            className="size-3 shrink-0 rounded"
            style={{ backgroundColor: color }}
          />
          <p className="text-text-neutral-primary text-xs leading-5 font-medium">
            {percentage}% {name}
          </p>
        </div>

        {/* Change percentage row */}
        {change !== undefined && (
          <div className="flex items-start">
            <p className="text-text-neutral-primary text-xs leading-5 font-medium">
              {change > 0 ? "+" : ""}
              {change}% Since last scan
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

const CustomLegend = ({ payload }: CustomLegendProps) => {
  const items = payload.map((entry: LegendPayloadEntry) => ({
    label: `${entry.value} (${entry.payload.percentage ?? 0}%)`,
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
  onSegmentClick,
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
      fill: CHART_COLORS.emptyState,
      color: CHART_COLORS.emptyState,
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

  // Reserve a small ring at the outer edge so the active sector can grow into
  // it without being clipped by the SVG viewport (consumers like
  // RequirementsStatusCard wrap the chart in a fixed-size box where
  // outerRadius == container/2 leaves no room to expand).
  const ACTIVE_GROW = 4;
  const restingOuterRadius = Math.max(
    innerRadius + 1,
    outerRadius - ACTIVE_GROW,
  );

  interface ActiveSectorProps {
    cx: number;
    cy: number;
    innerRadius: number;
    outerRadius: number;
    startAngle: number;
    endAngle: number;
    fill: string;
  }

  // Grows the hovered slice up to the original outerRadius so tiny segments
  // (e.g. 1% fail) are easy to see and target with the cursor (PROWLER-1477).
  // Recharts types `activeShape` as `(props: unknown) => Element`; cast on
  // the boundary so the body stays strongly typed.
  const renderActiveShape = (props: unknown) => {
    const p = props as ActiveSectorProps;
    return (
      <Sector
        cx={p.cx}
        cy={p.cy}
        innerRadius={p.innerRadius}
        outerRadius={p.outerRadius + ACTIVE_GROW}
        startAngle={p.startAngle}
        endAngle={p.endAngle}
        fill={p.fill}
      />
    );
  };

  return (
    <>
      <ChartContainer
        config={chartConfig}
        className="mx-auto aspect-square max-h-[350px]"
      >
        <PieChart>
          {!isEmpty && (
            <Tooltip
              content={<CustomTooltip />}
              cursor={false}
              wrapperStyle={{ zIndex: 1000 }}
            />
          )}
          <Pie
            data={isEmpty ? emptyData : chartData}
            dataKey="value"
            nameKey="name"
            innerRadius={innerRadius}
            outerRadius={restingOuterRadius}
            strokeWidth={0}
            paddingAngle={0}
            // `?? undefined` — Recharts treats `null` as truthy in some paths
            // and `||` would clobber index 0 (e.g. the "Pass" pillar).
            activeIndex={hoveredIndex ?? undefined}
            activeShape={renderActiveShape}
            onMouseEnter={(_, index) => {
              if (!isEmpty) setHoveredIndex(index);
            }}
            onMouseLeave={() => setHoveredIndex(null)}
          >
            {(isEmpty ? emptyData : chartData).map((entry, index) => {
              const opacity =
                hoveredIndex === null ? 1 : hoveredIndex === index ? 1 : 0.5;
              const isClickable = !isEmpty && onSegmentClick;
              return (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.fill}
                  opacity={opacity}
                  className={isClickable ? "cursor-pointer" : ""}
                  style={{
                    transition: "opacity 0.2s",
                  }}
                  onClick={() => {
                    if (isClickable) {
                      onSegmentClick(data[index], index);
                    }
                  }}
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
                          className="text-text-neutral-secondary text-2xl font-bold"
                          style={{
                            fill: "currentColor",
                          }}
                        >
                          {formattedValue}
                        </tspan>
                        <tspan
                          x={viewBox.cx}
                          y={(viewBox.cy || 0) + 24}
                          className="text-text-neutral-secondary text-sm text-nowrap"
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
