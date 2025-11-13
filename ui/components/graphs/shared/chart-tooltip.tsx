import { Bell, VolumeX } from "lucide-react";

import { cn } from "@/lib/utils";

import { TooltipData } from "../types";

interface MultiSeriesPayloadEntry {
  color?: string;
  name?: string;
  value?: string | number;
  dataKey?: string;
  payload?: Record<string, string | number | undefined>;
}

interface ChartTooltipProps {
  active?: boolean;
  payload?: MultiSeriesPayloadEntry[];
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

  const data: TooltipData = (payload[0].payload || payload[0]) as TooltipData;
  const color = payload[0].color || data.color;

  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
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
        <p className="text-text-neutral-primary text-sm font-semibold">
          {label || data.name}
        </p>
      </div>

      <p className="text-text-neutral-secondary mt-1 text-sm font-medium">
        {typeof data.value === "number"
          ? data.value.toLocaleString()
          : data.value}
        {data.percentage !== undefined && ` (${data.percentage}%)`}
      </p>

      {data.newFindings !== undefined && data.newFindings > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <Bell size={14} className="text-text-neutral-secondary" />
          <span className="text-text-neutral-secondary text-sm font-medium">
            {data.newFindings} New Findings
          </span>
        </div>
      )}

      {data.new !== undefined && data.new > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <Bell size={14} className="text-text-neutral-secondary" />
          <span className="text-text-neutral-secondary text-sm font-medium">
            {data.new} New
          </span>
        </div>
      )}

      {data.muted !== undefined && data.muted > 0 && (
        <div className="mt-1 flex items-center gap-2">
          <VolumeX size={14} className="text-text-neutral-secondary" />
          <span className="text-text-neutral-secondary text-sm font-medium">
            {data.muted} Muted
          </span>
        </div>
      )}

      {data.change !== undefined && (
        <p className="text-text-neutral-secondary mt-1 text-sm font-medium">
          <span className="font-bold">
            {(data.change as number) > 0 ? "+" : ""}
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
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
      <p className="text-text-neutral-primary mb-2 text-sm font-semibold">
        {label}
      </p>

      {payload.map((entry: MultiSeriesPayloadEntry, index: number) => (
        <div key={index} className="flex items-center gap-2">
          <div
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-text-neutral-secondary text-sm font-medium">
            {entry.name}:
          </span>
          <span className="text-text-neutral-secondary text-sm font-semibold">
            {entry.value}
          </span>
          {entry.payload && entry.payload[`${entry.dataKey}_change`] && (
            <span className="text-text-neutral-secondary text-sm font-medium">
              (
              {(entry.payload[`${entry.dataKey}_change`] as number) > 0
                ? "+"
                : ""}
              {entry.payload[`${entry.dataKey}_change`]}%)
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
