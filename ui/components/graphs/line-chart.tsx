"use client";

import { Bell } from "lucide-react";
import { useState } from "react";
import {
  CartesianGrid,
  Legend,
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
import { CHART_COLORS } from "./shared/constants";
import {
  AXIS_FONT_SIZE,
  CustomXAxisTickWithToday,
} from "./shared/custom-axis-tick";
import { LineConfig, LineDataPoint } from "./types";

interface LineChartProps {
  data: LineDataPoint[];
  lines: LineConfig[];
  height?: number;
}

interface TooltipPayloadItem {
  dataKey: string;
  value: number;
  stroke: string;
  name: string;
  payload: LineDataPoint;
}

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

  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
      <p className="text-text-neutral-secondary mb-3 text-xs">{label}</p>

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

const CustomLegend = ({ payload }: any) => {
  const severityOrder = [
    "Informational",
    "Low",
    "Medium",
    "High",
    "Critical",
    "Muted",
  ];

  const sortedPayload = [...payload].sort((a, b) => {
    const indexA = severityOrder.indexOf(a.value);
    const indexB = severityOrder.indexOf(b.value);
    return indexA - indexB;
  });

  const items = sortedPayload.map((entry: any) => ({
    label: entry.value,
    color: entry.color,
  }));

  return <ChartLegend items={items} />;
};

const chartConfig = {
  default: {
    color: "var(--chart-1)",
  },
} satisfies ChartConfig;

export function LineChart({ data, lines, height = 400 }: LineChartProps) {
  const [hoveredLine, setHoveredLine] = useState<string | null>(null);

  return (
    <ChartContainer
      config={chartConfig}
      className="w-full"
      style={{ height, aspectRatio: "auto" }}
    >
      <RechartsLine
        data={data}
        margin={{
          top: 10,
          left: 50,
          right: 30,
          bottom: 20,
        }}
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
          tick={CustomXAxisTickWithToday}
        />
        <YAxis
          tickLine={false}
          axisLine={false}
          tickMargin={8}
          tick={{
            fill: CHART_COLORS.textSecondary,
            fontSize: AXIS_FONT_SIZE,
          }}
        />
        <ChartTooltip cursor={false} content={<CustomLineTooltip />} />
        <Legend
          content={<CustomLegend />}
          wrapperStyle={{ paddingTop: "40px" }}
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
              strokeOpacity={isFaded ? 0.5 : 1}
              name={line.label}
              dot={{ fill: line.color, r: 4 }}
              activeDot={{ r: 6 }}
              onMouseEnter={() => setHoveredLine(line.dataKey)}
              onMouseLeave={() => setHoveredLine(null)}
              style={{ transition: "stroke-opacity 0.2s" }}
            />
          );
        })}
      </RechartsLine>
    </ChartContainer>
  );
}
