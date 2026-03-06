"use client";

import { Bell } from "lucide-react";
import { useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart as RechartsLine,
  TooltipProps,
  XAxis,
  YAxis,
} from "recharts";

import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
} from "@/components/ui/chart/Chart";

import { AlertPill } from "./shared/alert-pill";
import { ChartLegend } from "./shared/chart-legend";
import { CustomActiveDot, PointClickData } from "./shared/custom-active-dot";
import {
  AXIS_FONT_SIZE,
  CustomXAxisTickWithToday,
} from "./shared/custom-axis-tick";
import { CustomDot } from "./shared/custom-dot";
import { LineConfig, LineDataPoint } from "./types";

interface LineChartProps {
  data: LineDataPoint[];
  lines: LineConfig[];
  height?: number;
  xAxisInterval?: number | "preserveStart" | "preserveEnd" | "preserveStartEnd";
  onPointClick?: (data: PointClickData) => void;
}

interface TooltipPayloadItem {
  dataKey: string;
  value: number;
  stroke: string;
  name: string;
  payload: LineDataPoint;
}

const formatTooltipDate = (dateStr: string) => {
  const date = new Date(dateStr);
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
};

interface CustomLineTooltipProps extends TooltipProps<number, string> {
  filterLine?: string | null;
}

const CustomLineTooltip = ({
  active,
  payload,
  label,
  filterLine,
}: CustomLineTooltipProps) => {
  if (!active || !payload || payload.length === 0) {
    return null;
  }

  const typedPayload = payload as unknown as TooltipPayloadItem[];

  // Filter payload if a line is selected or hovered
  const filteredPayload = filterLine
    ? typedPayload.filter((item) => item.dataKey === filterLine)
    : typedPayload;

  // Sort by severity order: critical, high, medium, low, informational
  const severityOrder = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
  ] as const;
  const displayPayload = [...filteredPayload].sort((a, b) => {
    const aIndex = severityOrder.indexOf(
      a.dataKey as (typeof severityOrder)[number],
    );
    const bIndex = severityOrder.indexOf(
      b.dataKey as (typeof severityOrder)[number],
    );
    // Items not in severityOrder go to the end
    if (aIndex === -1) return 1;
    if (bIndex === -1) return -1;
    return aIndex - bIndex;
  });

  if (displayPayload.length === 0) {
    return null;
  }

  const totalValue = displayPayload.reduce((sum, item) => sum + item.value, 0);
  const formattedDate = formatTooltipDate(String(label));

  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
      <p className="text-text-neutral-secondary mb-3 text-xs">
        {formattedDate}
      </p>

      <div className="mb-3">
        <AlertPill value={totalValue} textSize="sm" />
      </div>

      <div className="space-y-3">
        {displayPayload.map((item) => {
          const newFindings = item.payload[`${item.dataKey}_newFindings`];
          const change = item.payload[`${item.dataKey}_change`];

          return (
            <div key={item.dataKey} className="space-y-1">
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                  <div
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: item.stroke }}
                  />
                  <span className="text-text-neutral-secondary text-sm">
                    {item.name}
                  </span>
                </div>
                <span className="text-text-neutral-primary text-sm font-medium">
                  {item.value}
                </span>
              </div>
              {newFindings !== undefined && (
                <div className="flex items-center gap-2">
                  <Bell size={14} className="text-text-neutral-secondary" />
                  <span className="text-text-neutral-secondary text-xs">
                    {newFindings} New Findings
                  </span>
                </div>
              )}
              {change !== undefined && typeof change === "number" && (
                <p className="text-text-neutral-secondary text-xs">
                  <span className="font-bold">
                    {(change as number) > 0 ? "+" : ""}
                    {change}%
                  </span>{" "}
                  Since Last Scan
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

const chartConfig = {
  default: {
    color: "var(--color-bg-data-azure)",
  },
} satisfies ChartConfig;

export function LineChart({
  data,
  lines,
  height = 400,
  xAxisInterval = "preserveStartEnd",
  onPointClick,
}: LineChartProps) {
  const [hoveredLine, setHoveredLine] = useState<string | null>(null);
  const [selectedLine, setSelectedLine] = useState<string | null>(null);

  // Active line is either selected (persistent) or hovered (temporary)
  const activeLine = selectedLine ?? hoveredLine;

  const legendItems = lines.map((line) => ({
    label: line.label,
    color: line.color,
    dataKey: line.dataKey,
  }));

  const handleLegendClick = (dataKey: string) => {
    // Toggle selection: if already selected, deselect; otherwise select
    setSelectedLine((current) => (current === dataKey ? null : dataKey));
  };

  return (
    <div className="w-full">
      <ChartContainer
        config={chartConfig}
        className="w-full"
        style={{ height, aspectRatio: "auto" }}
      >
        <RechartsLine
          data={data}
          margin={{
            top: 20,
            left: 0,
            right: 30,
            bottom: 40,
          }}
          style={{ cursor: onPointClick ? "pointer" : "default" }}
        >
          <CartesianGrid
            vertical={false}
            strokeOpacity={1}
            stroke="var(--border-neutral-secondary)"
          />
          <XAxis
            dataKey="date"
            tickLine={false}
            axisLine={false}
            tickMargin={8}
            interval={xAxisInterval}
            tick={(props) => (
              <CustomXAxisTickWithToday {...props} data={data} />
            )}
          />
          <YAxis
            tickLine={false}
            axisLine={false}
            tickMargin={8}
            padding={{ top: 20 }}
            tick={{
              fill: "var(--color-text-neutral-secondary)",
              fontSize: AXIS_FONT_SIZE,
            }}
          />
          <ChartTooltip
            cursor={{
              stroke: "var(--color-text-neutral-tertiary)",
              strokeWidth: 1,
              strokeDasharray: "4 4",
            }}
            content={<CustomLineTooltip filterLine={activeLine} />}
          />
          {lines.map((line) => {
            const isActive = activeLine === line.dataKey;
            const isFaded = activeLine !== null && !isActive;
            return (
              <Line
                key={line.dataKey}
                type="natural"
                dataKey={line.dataKey}
                stroke={line.color}
                strokeWidth={2}
                strokeOpacity={isFaded ? 0.2 : 1}
                name={line.label}
                dot={({
                  key,
                  ...props
                }: {
                  key?: string;
                  cx?: number;
                  cy?: number;
                }) => (
                  <CustomDot
                    key={key}
                    {...props}
                    color={line.color}
                    isFaded={isFaded}
                  />
                )}
                activeDot={(props: {
                  cx?: number;
                  cy?: number;
                  payload?: LineDataPoint;
                }) => (
                  <CustomActiveDot
                    {...props}
                    dataKey={line.dataKey}
                    color={line.color}
                    isFaded={isFaded}
                    onPointClick={onPointClick}
                    onMouseEnter={() => setHoveredLine(line.dataKey)}
                    onMouseLeave={() => setHoveredLine(null)}
                  />
                )}
                style={{ transition: "stroke-opacity 0.2s" }}
              />
            );
          })}
        </RechartsLine>
      </ChartContainer>

      <div className="mt-4 flex flex-col items-start gap-2">
        <p className="text-text-neutral-tertiary pl-2 text-xs">
          Click to filter by severity
        </p>
        <ChartLegend
          items={legendItems}
          selectedItem={selectedLine}
          onItemClick={handleLegendClick}
        />
      </div>
    </div>
  );
}
