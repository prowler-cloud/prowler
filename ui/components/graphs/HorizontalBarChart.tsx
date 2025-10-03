"use client";

import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  XAxis,
  YAxis,
} from "recharts";

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
  Info: "#2E51B2",
  Informational: "#2E51B2",
  Low: "#FDD34F",
  Medium: "#FF7D19",
  High: "#FF3077",
  Critical: "#971348",
};

type SortOption = "high-low" | "low-high" | "alphabetical";

export function HorizontalBarChart({
  data,
  height = 400,
  showSortDropdown = true,
  title,
}: HorizontalBarChartProps) {
  const [sortBy, setSortBy] = useState<SortOption>("high-low");

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
          {title && <h3 className="text-lg font-semibold text-white">{title}</h3>}
          {showSortDropdown && (
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortOption)}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 focus:border-slate-600 focus:outline-none"
            >
              <option value="high-low">Risk high-low</option>
              <option value="low-high">Risk low-high</option>
              <option value="alphabetical">Alphabetical</option>
            </select>
          )}
        </div>
      )}

      <div className="space-y-6">
        {sortedData.map((item, index) => (
          <div key={index} className="flex items-center gap-4">
            {/* Category Label */}
            <div className="w-24 text-right">
              <span className="text-sm text-slate-300">{item.name}</span>
            </div>

            {/* Bar */}
            <div className="flex-1">
              <div className="relative h-8 w-full rounded-lg bg-slate-700/50">
                <div
                  className="h-full rounded-lg transition-all duration-300"
                  style={{
                    width: `${item.percentage || (item.value / Math.max(...data.map(d => d.value)) * 100)}%`,
                    backgroundColor: item.color || SEVERITY_COLORS[item.name] || "#6B7280",
                  }}
                />
              </div>
            </div>

            {/* Legend - Percentage and Value */}
            <div className="flex w-40 items-center gap-2 text-sm text-slate-300">
              <span className="font-semibold">{item.percentage}%</span>
              <span className="text-slate-500">•</span>
              <span>{item.value.toLocaleString()}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
