import { Bell, VolumeX } from "lucide-react";

import { TooltipData } from "../models/chart-types";
import { CHART_COLORS } from "./chart-constants";

interface ChartTooltipProps {
  active?: boolean;
  payload?: any[];
  label?: string;
  showColorIndicator?: boolean;
  colorIndicatorShape?: "circle" | "square";
}

export function ChartTooltip({
  active,
  payload,
  label,
  showColorIndicator = true,
  colorIndicatorShape = "square",
}: ChartTooltipProps) {
  if (!active || !payload || payload.length === 0) {
    return null;
  }

  const data: TooltipData = payload[0].payload || payload[0];
  const color = payload[0].color || data.color;

  return (
    <div
      className="rounded-lg border p-3 shadow-lg"
      style={{
        borderColor: CHART_COLORS.tooltipBorder,
        backgroundColor: CHART_COLORS.tooltipBackground,
        minWidth: "200px",
      }}
    >
      <div className="flex items-center gap-2">
        {showColorIndicator && color && (
          <div
            className={
              colorIndicatorShape === "circle" ? "rounded-full" : "rounded-sm"
            }
            style={{
              backgroundColor: color,
              width: "12px",
              height: "12px",
            }}
          />
        )}
        <p
          className="text-sm font-semibold"
          style={{ color: CHART_COLORS.textPrimary }}
        >
          {label || data.name}
        </p>
      </div>

      <p className="mt-1 text-xs" style={{ color: CHART_COLORS.textPrimary }}>
        {typeof data.value === "number"
          ? data.value.toLocaleString()
          : data.value}
        {data.percentage !== undefined && ` (${data.percentage}%)`}
      </p>

      {data.newFindings !== undefined && data.newFindings > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <Bell size={14} style={{ color: CHART_COLORS.textSecondary }} />
          <span className="text-xs" style={{ color: CHART_COLORS.textSecondary }}>
            {data.newFindings} New Findings
          </span>
        </div>
      )}

      {data.new !== undefined && data.new > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <Bell size={14} style={{ color: CHART_COLORS.textSecondary }} />
          <span className="text-xs" style={{ color: CHART_COLORS.textSecondary }}>
            {data.new} New
          </span>
        </div>
      )}

      {data.muted !== undefined && data.muted > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <VolumeX size={14} style={{ color: CHART_COLORS.textSecondary }} />
          <span className="text-xs" style={{ color: CHART_COLORS.textSecondary }}>
            {data.muted} Muted
          </span>
        </div>
      )}

      {data.change !== undefined && (
        <p className="mt-1 text-xs" style={{ color: CHART_COLORS.textSecondary }}>
          <span className="font-bold">
            {data.change > 0 ? "+" : ""}
            {data.change}%
          </span>{" "}
          Since Last Scan
        </p>
      )}
    </div>
  );
}

/**
 * Tooltip for charts with multiple data series (like LineChart)
 */
export function MultiSeriesChartTooltip({
  active,
  payload,
  label,
}: ChartTooltipProps) {
  if (!active || !payload || payload.length === 0) {
    return null;
  }

  return (
    <div
      className="rounded-lg border p-3 shadow-lg"
      style={{
        borderColor: CHART_COLORS.tooltipBorder,
        backgroundColor: CHART_COLORS.tooltipBackground,
        minWidth: "200px",
      }}
    >
      <p
        className="mb-2 text-sm font-semibold"
        style={{ color: CHART_COLORS.textPrimary }}
      >
        {label}
      </p>

      {payload.map((entry: any, index: number) => (
        <div key={index} className="flex items-center gap-2">
          <div
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-xs" style={{ color: CHART_COLORS.textPrimary }}>
            {entry.name}:
          </span>
          <span
            className="text-xs font-semibold"
            style={{ color: CHART_COLORS.textPrimary }}
          >
            {entry.value}
          </span>
          {entry.payload[`${entry.dataKey}_change`] && (
            <span
              className="text-xs"
              style={{ color: CHART_COLORS.textSecondary }}
            >
              ({entry.payload[`${entry.dataKey}_change`] > 0 ? "+" : ""}
              {entry.payload[`${entry.dataKey}_change`]}%)
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
