"use client";

import { Bell } from "lucide-react";
import { useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart as RechartsLine,
  ResponsiveContainer,
  Tooltip,
  TooltipProps,
  XAxis,
  YAxis,
} from "recharts";

import { AlertPill } from "./shared/alert-pill";
import { ChartLegend } from "./shared/chart-legend";
import { CHART_COLORS } from "./shared/constants";
import { LineConfig, LineDataPoint } from "./types";

interface LineChartProps {
  data: LineDataPoint[];
  lines: LineConfig[];
  xLabel?: string;
  yLabel?: string;
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
    <div
      className="rounded-lg border p-3 shadow-lg"
      style={{
        backgroundColor: "var(--chart-background)",
        borderColor: "var(--chart-border-emphasis)",
      }}
    >
      <p className="mb-3 text-xs" style={{ color: "var(--chart-text-secondary)" }}>
        {label}
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
                <span className="text-sm" style={{ color: "var(--chart-text-primary)" }}>
                  {item.value}
                </span>
              </div>
              {newFindings !== undefined && (
                <div className="flex items-center gap-2">
                  <Bell size={14} style={{ color: "var(--chart-text-secondary)" }} />
                  <span
                    className="text-xs"
                    style={{ color: "var(--chart-text-secondary)" }}
                  >
                    {newFindings} New Findings
                  </span>
                </div>
              )}
              {change !== undefined && typeof change === "number" && (
                <p className="text-xs" style={{ color: "var(--chart-text-secondary)" }}>
                  <span className="font-bold">
                    {change > 0 ? "+" : ""}
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

export function LineChart({
  data,
  lines,
  xLabel,
  yLabel,
  height = 400,
}: LineChartProps) {
  const [hoveredLine, setHoveredLine] = useState<string | null>(null);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsLine
        data={data}
        margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke={CHART_COLORS.gridLine} />
        <XAxis
          dataKey="date"
          label={
            xLabel
              ? {
                  value: xLabel,
                  position: "insideBottom",
                  offset: -10,
                  fill: CHART_COLORS.textSecondary,
                }
              : undefined
          }
          tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }}
        />
        <YAxis
          label={
            yLabel
              ? {
                  value: yLabel,
                  angle: -90,
                  position: "insideLeft",
                  fill: CHART_COLORS.textSecondary,
                }
              : undefined
          }
          tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }}
        />
        <Tooltip content={<CustomLineTooltip />} />
        <Legend content={<CustomLegend />} />
        {lines.map((line) => {
          const isHovered = hoveredLine === line.dataKey;
          const isFaded = hoveredLine !== null && !isHovered;
          return (
            <Line
              key={line.dataKey}
              type="monotone"
              dataKey={line.dataKey}
              stroke={line.color}
              strokeWidth={2}
              strokeOpacity={isFaded ? 0.5 : 1}
              name={line.label}
              dot={{ fill: line.color, r: 4, opacity: isFaded ? 0.5 : 1 }}
              activeDot={{ r: 6 }}
              onMouseEnter={() => setHoveredLine(line.dataKey)}
              onMouseLeave={() => setHoveredLine(null)}
              style={{ transition: "stroke-opacity 0.2s" }}
            />
          );
        })}
      </RechartsLine>
    </ResponsiveContainer>
  );
}
