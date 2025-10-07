"use client";

import { useState } from "react";

interface BarDataPoint {
  name: string;
  value: number;
  percentage?: number;
  color?: string;
  change?: number;
  newFindings?: number;
}

interface HorizontalBarChartProps {
  data: BarDataPoint[];
  height?: number;
  showSortDropdown?: boolean;
  title?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  Info: "var(--color-info)",
  Informational: "var(--color-info)",
  Low: "var(--color-warning)",
  Medium: "var(--color-warning-emphasis)",
  High: "var(--color-danger)",
  Critical: "var(--color-danger-emphasis)",
};

const SORT_OPTIONS = {
  "high-low": "high-low",
  "low-high": "low-high",
  alphabetical: "alphabetical",
} as const;

type SortOption = (typeof SORT_OPTIONS)[keyof typeof SORT_OPTIONS];

export function HorizontalBarChart({
  data,
  showSortDropdown = true,
  title,
}: HorizontalBarChartProps) {
  const [sortBy, setSortBy] = useState<SortOption>("high-low");
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const sortedData = [...data].sort((a, b) => {
    switch (sortBy) {
      case "high-low":
        return b.value - a.value;
      case "low-high":
        return a.value - b.value;
      case "alphabetical":
        return a.name.localeCompare(b.name);
      default:
        return 0;
    }
  });

  return (
    <div className="w-full">
      {(title || showSortDropdown) && (
        <div className="mb-4 flex items-center justify-between">
          {title && (
            <h3
              className="text-lg font-semibold"
              style={{ color: "var(--color-white)" }}
            >
              {title}
            </h3>
          )}
          {showSortDropdown && (
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortOption)}
              className="rounded-lg border px-3 py-2 text-sm focus:outline-none"
              style={{
                borderColor: "var(--color-slate-700)",
                backgroundColor: "var(--color-slate-800)",
                color: "var(--color-white)",
              }}
            >
              <option value="high-low">Risk high-low</option>
              <option value="low-high">Risk low-high</option>
              <option value="alphabetical">Alphabetical</option>
            </select>
          )}
        </div>
      )}

      <div className="space-y-6">
        {sortedData.map((item, index) => {
          const isHovered = hoveredIndex === index;
          const isFaded = hoveredIndex !== null && !isHovered;
          const barColor =
            item.color || SEVERITY_COLORS[item.name] || "#6B7280";

          return (
            <div
              key={index}
              className="relative flex items-center gap-4"
              onMouseEnter={() => setHoveredIndex(index)}
              onMouseLeave={() => setHoveredIndex(null)}
            >
              {/* Category Label */}
              <div className="w-24 text-right">
                <span
                  className="text-sm"
                  style={{
                    color: "var(--color-white)",
                    opacity: isFaded ? 0.5 : 1,
                    transition: "opacity 0.2s",
                  }}
                >
                  {item.name}
                </span>
              </div>

              {/* Bar */}
              <div className="relative flex-1">
                {/* Background track */}
                <div
                  className="absolute inset-0 h-8 w-full rounded-lg"
                  style={{
                    backgroundColor: "rgba(51, 65, 85, 0.5)", // slate-700 with 50% opacity
                  }}
                />
                {/* Colored bar */}
                <div
                  className="relative h-8 rounded-lg transition-all duration-300"
                  style={{
                    width: `${item.percentage || (item.value / Math.max(...data.map((d) => d.value))) * 100}%`,
                    backgroundColor: barColor,
                    opacity: isFaded ? 0.5 : 1,
                  }}
                />

                {/* Tooltip on Hover */}
                {isHovered && (
                  <div
                    className="absolute top-10 left-0 z-10 rounded-lg border p-3 shadow-lg"
                    style={{
                      backgroundColor: "var(--color-slate-800)",
                      borderColor: "var(--color-slate-700)",
                      minWidth: "200px",
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <div
                        className="h-3 w-3 rounded-sm"
                        style={{ backgroundColor: barColor }}
                      />
                      <span
                        className="font-semibold"
                        style={{ color: "var(--color-white)" }}
                      >
                        {item.value.toLocaleString()} {item.name} Risk
                      </span>
                    </div>
                    {item.newFindings !== undefined && (
                      <div
                        className="mt-2 flex items-center gap-1 text-sm"
                        style={{ color: "var(--color-slate-400)" }}
                      >
                        <span>△</span>
                        <span>{item.newFindings} New Findings</span>
                      </div>
                    )}
                    {item.change !== undefined && (
                      <div
                        className="mt-1 text-sm"
                        style={{ color: "var(--color-slate-400)" }}
                      >
                        {item.change > 0 ? "+" : ""}
                        {item.change}% Since last scan
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Legend - Percentage and Value */}
              <div
                className="flex w-40 items-center gap-2 text-sm"
                style={{
                  color: "var(--color-white)",
                  opacity: isFaded ? 0.5 : 1,
                  transition: "opacity 0.2s",
                }}
              >
                <span className="font-semibold">{item.percentage}%</span>
                <span style={{ color: "var(--color-slate-400)" }}>•</span>
                <span>{item.value.toLocaleString()}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
