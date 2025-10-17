import { Bell, VolumeX } from "lucide-react";

import { cn } from "@/lib/utils";

import { TooltipData } from "../types";

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
    <div className="min-w-[200px] rounded-lg border border-slate-700 bg-slate-800 p-3 shadow-lg">
      <div className="flex items-center gap-2">
        {showColorIndicator && color && (
          <div
            className={cn(
              "h-3 w-3",
              colorIndicatorShape === "circle" ? "rounded-full" : "rounded-sm",
            )}
            style={{ backgroundColor: color }}
          />
        )}
        <p className="text-sm font-semibold text-white">{label || data.name}</p>
      </div>

      <p className="mt-1 text-xs text-white">
        {typeof data.value === "number"
          ? data.value.toLocaleString()
          : data.value}
        {data.percentage !== undefined && ` (${data.percentage}%)`}
      </p>

      {data.newFindings !== undefined && data.newFindings > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <Bell size={14} className="text-slate-400" />
          <span className="text-xs text-slate-400">
            {data.newFindings} New Findings
          </span>
        </div>
      )}

      {data.new !== undefined && data.new > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <Bell size={14} className="text-slate-400" />
          <span className="text-xs text-slate-400">{data.new} New</span>
        </div>
      )}

      {data.muted !== undefined && data.muted > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <VolumeX size={14} className="text-slate-400" />
          <span className="text-xs text-slate-400">{data.muted} Muted</span>
        </div>
      )}

      {data.change !== undefined && (
        <p className="mt-1 text-xs text-slate-400">
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
    <div className="min-w-[200px] rounded-lg border border-slate-700 bg-slate-800 p-3 shadow-lg">
      <p className="mb-2 text-sm font-semibold text-white">{label}</p>

      {payload.map((entry: any, index: number) => (
        <div key={index} className="flex items-center gap-2">
          <div
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-xs text-white">{entry.name}:</span>
          <span className="text-xs font-semibold text-white">
            {entry.value}
          </span>
          {entry.payload[`${entry.dataKey}_change`] && (
            <span className="text-xs text-slate-400">
              ({entry.payload[`${entry.dataKey}_change`] > 0 ? "+" : ""}
              {entry.payload[`${entry.dataKey}_change`]}%)
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
