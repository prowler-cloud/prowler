"use client";

import { Bell } from "lucide-react";
import { useState } from "react";
import {
  CartesianGrid,
  Dot,
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
import {
  AXIS_FONT_SIZE,
  CustomXAxisTickWithToday,
} from "./shared/custom-axis-tick";
import { LineConfig, LineDataPoint } from "./types";

interface PointClickData {
  point: LineDataPoint;
  dataKey?: string;
}

interface ActiveDotProps {
  cx?: number;
  cy?: number;
  payload?: LineDataPoint;
  dataKey: string;
  color: string;
  onPointClick?: (data: PointClickData) => void;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}

const CustomActiveDot = ({
  cx,
  cy,
  payload,
  dataKey,
  color,
  onPointClick,
  onMouseEnter,
  onMouseLeave,
}: ActiveDotProps) => {
  if (cx === undefined || cy === undefined) return null;

  return (
    <Dot
      cx={cx}
      cy={cy}
      r={6}
      fill={color}
      style={{ cursor: onPointClick ? "pointer" : "default" }}
      onClick={() => {
        if (onPointClick && payload) {
          onPointClick({ point: payload, dataKey });
        }
      }}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    />
  );
};

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

const CustomLineTooltip = ({
  active,
  payload,
  label,
}: TooltipProps<number, string>) => {
  if (!active || !payload || payload.length === 0) {
    return null;
  }

  const typedPayload = payload as unknown as TooltipPayloadItem[];
  const totalValue = typedPayload.reduce((sum, item) => sum + item.value, 0);
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
        {typedPayload.map((item) => {
          const newFindings = item.payload[`${item.dataKey}_newFindings`];
          const change = item.payload[`${item.dataKey}_change`];

          return (
            <div key={item.dataKey} className="space-y-1">
              <div className="flex items-center gap-2">
                <div
                  className="h-2 w-2 rounded-full"
                  style={{ backgroundColor: item.stroke }}
                />
                <span className="text-text-neutral-primary text-sm">
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

  const legendItems = lines.map((line) => ({
    label: line.label,
    color: line.color,
  }));

  return (
    <div className="w-full">
      <ChartContainer
        config={chartConfig}
        className="w-full overflow-hidden"
        style={{ height, aspectRatio: "auto" }}
      >
        <RechartsLine
          data={data}
          margin={{
            top: 10,
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
            content={<CustomLineTooltip />}
          />
          {lines.map((line) => {
            const isHovered = hoveredLine === line.dataKey;
            const isFaded = hoveredLine !== null && !isHovered;
            return (
              <Line
                key={line.dataKey}
                type="natural"
                dataKey={line.dataKey}
                stroke={line.color}
                strokeWidth={2}
                strokeOpacity={isFaded ? 0.2 : 1}
                name={line.label}
                dot={{ fill: line.color, r: 4 }}
                activeDot={(props: { cx?: number; cy?: number; payload?: LineDataPoint }) => (
                  <CustomActiveDot
                    {...props}
                    dataKey={line.dataKey}
                    color={line.color}
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

      <div className="mt-4">
        <ChartLegend items={legendItems} />
      </div>
    </div>
  );
}
