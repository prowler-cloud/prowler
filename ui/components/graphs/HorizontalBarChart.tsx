"use client";

import { Bell } from "lucide-react";
import { useState } from "react";

import { BarDataPoint } from "./models/chart-types";
import { SEVERITY_ORDER } from "./shared/constants";
import { getSeverityColorByName } from "./shared/utils";

interface HorizontalBarChartProps {
  data: BarDataPoint[];
  height?: number;
  title?: string;
}

export function HorizontalBarChart({ data, title }: HorizontalBarChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const sortedData = [...data].sort((a, b) => {
    const orderA = SEVERITY_ORDER[a.name as keyof typeof SEVERITY_ORDER] ?? 999;
    const orderB = SEVERITY_ORDER[b.name as keyof typeof SEVERITY_ORDER] ?? 999;
    return orderA - orderB;
  });

  return (
    <div className="w-full">
      {title && (
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-white">{title}</h3>
        </div>
      )}

      <div className="space-y-6">
        {sortedData.map((item, index) => {
          const isHovered = hoveredIndex === index;
          const isFaded = hoveredIndex !== null && !isHovered;
          const barColor =
            item.color || getSeverityColorByName(item.name) || "#6B7280";

          return (
            <div
              key={index}
              className="relative flex items-center gap-4"
              onMouseEnter={() => setHoveredIndex(index)}
              onMouseLeave={() => setHoveredIndex(null)}
            >
              <div className="w-24 text-right">
                <span
                  className="text-sm text-white"
                  style={{
                    opacity: isFaded ? 0.5 : 1,
                    transition: "opacity 0.2s",
                  }}
                >
                  {item.name}
                </span>
              </div>

              <div className="relative flex-1">
                <div className="absolute inset-0 h-8 w-full rounded-lg bg-slate-700/50" />
                <div
                  className="relative h-8 rounded-lg transition-all duration-300"
                  style={{
                    width: `${item.percentage || (item.value / Math.max(...data.map((d) => d.value))) * 100}%`,
                    backgroundColor: barColor,
                    opacity: isFaded ? 0.5 : 1,
                  }}
                />

                {isHovered && (
                  <div className="absolute top-10 left-0 z-10 min-w-[200px] rounded-lg border border-slate-700 bg-slate-800 p-3 shadow-lg">
                    <div className="flex items-center gap-2">
                      <div
                        className="h-3 w-3 rounded-sm"
                        style={{ backgroundColor: barColor }}
                      />
                      <span className="font-semibold text-white">
                        {item.value.toLocaleString()} {item.name} Risk
                      </span>
                    </div>
                    {item.newFindings !== undefined && (
                      <div className="mt-2 flex items-center gap-2">
                        <Bell size={14} className="text-slate-400" />
                        <span className="text-sm text-slate-400">
                          {item.newFindings} New Findings
                        </span>
                      </div>
                    )}
                    {item.change !== undefined && (
                      <p className="mt-1 text-sm text-slate-400">
                        <span className="font-bold">
                          {item.change > 0 ? "+" : ""}
                          {item.change}%
                        </span>{" "}
                        Since Last Scan
                      </p>
                    )}
                  </div>
                )}
              </div>

              <div
                className="flex w-40 items-center gap-2 text-sm text-white"
                style={{
                  opacity: isFaded ? 0.5 : 1,
                  transition: "opacity 0.2s",
                }}
              >
                <span className="font-semibold">{item.percentage}%</span>
                <span className="text-slate-400">•</span>
                <span>{item.value.toLocaleString()}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
