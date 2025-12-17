"use client";

import { Bell } from "lucide-react";
import { useState } from "react";

import { cn } from "@/lib/utils";

import { SEVERITY_ORDER } from "./shared/constants";
import { getSeverityColorByName } from "./shared/utils";
import { BarDataPoint } from "./types";

interface HorizontalBarChartProps {
  data: BarDataPoint[];
  height?: number;
  title?: string;
  onBarClick?: (dataPoint: BarDataPoint, index: number) => void;
}

export function HorizontalBarChart({
  data,
  title,
  onBarClick,
}: HorizontalBarChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const total = data.reduce((sum, d) => sum + (Number(d.value) || 0), 0);
  const isEmpty = total <= 0;

  const emptyData: BarDataPoint[] = [
    { name: "Critical", value: 1, percentage: 100 },
    { name: "High", value: 1, percentage: 100 },
    { name: "Medium", value: 1, percentage: 100 },
    { name: "Low", value: 1, percentage: 100 },
    { name: "Informational", value: 1, percentage: 100 },
  ];

  const sortedData = (isEmpty ? emptyData : [...data]).sort((a, b) => {
    const orderA = SEVERITY_ORDER[a.name as keyof typeof SEVERITY_ORDER] ?? 999;
    const orderB = SEVERITY_ORDER[b.name as keyof typeof SEVERITY_ORDER] ?? 999;
    return orderA - orderB;
  });

  return (
    <div className="w-full space-y-6">
      {title && (
        <div>
          <h3 className="text-text-neutral-primary text-lg font-semibold">
            {title}
          </h3>
        </div>
      )}

      <div className="space-y-6">
        {sortedData.map((item, index) => {
          const isHovered = !isEmpty && hoveredIndex === index;
          const isFaded = !isEmpty && hoveredIndex !== null && !isHovered;
          const barColor = isEmpty
            ? "var(--bg-neutral-tertiary)"
            : item.color ||
              getSeverityColorByName(item.name) ||
              "var(--bg-neutral-tertiary)";

          const isClickable = !isEmpty && onBarClick;
          const maxValue =
            data.length > 0 ? Math.max(...data.map((d) => d.value)) : 0;
          const calculatedWidth = isEmpty
            ? item.percentage
            : (item.percentage ??
              (maxValue > 0 ? (item.value / maxValue) * 100 : 0));
          // Calculate display percentage (value / total * 100)
          const displayPercentage = isEmpty
            ? 0
            : (item.percentage ??
              (total > 0 ? Math.round((item.value / total) * 100) : 0));
          return (
            <div
              key={item.name}
              className={cn(
                "flex items-center gap-6",
                isClickable && "cursor-pointer",
              )}
              role={isClickable ? "button" : undefined}
              tabIndex={isClickable ? 0 : undefined}
              onMouseEnter={() => !isEmpty && setHoveredIndex(index)}
              onMouseLeave={() => !isEmpty && setHoveredIndex(null)}
              onClick={() => {
                if (isClickable) {
                  const originalIndex = data.findIndex(
                    (d) => d.name === item.name,
                  );
                  onBarClick(data[originalIndex], originalIndex);
                }
              }}
              onKeyDown={(e) => {
                if (isClickable && (e.key === "Enter" || e.key === " ")) {
                  e.preventDefault();
                  const originalIndex = data.findIndex(
                    (d) => d.name === item.name,
                  );
                  onBarClick(data[originalIndex], originalIndex);
                }
              }}
            >
              {/* Label */}
              <div className="w-20 shrink-0">
                <span
                  className="text-text-neutral-secondary block truncate text-sm font-medium"
                  style={{
                    opacity: isFaded ? 0.5 : 1,
                    transition: "opacity 0.2s",
                  }}
                  title={item.name}
                >
                  {item.name === "Informational" ? "Info" : item.name}
                </span>
              </div>

              {/* Bar - flexible */}
              <div className="relative h-[22px] flex-1">
                <div className="bg-bg-neutral-tertiary absolute inset-0 h-[22px] w-full rounded-sm" />
                {(item.value > 0 || isEmpty) && (
                  <div
                    className="relative h-[22px] rounded-sm border border-black/10 transition-all duration-300"
                    style={{
                      width: `${calculatedWidth}%`,
                      backgroundColor: barColor,
                      opacity: isFaded ? 0.5 : 1,
                    }}
                  />
                )}

                {isHovered && (
                  <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary absolute top-10 left-0 z-10 rounded-xl border px-3 py-1.5 shadow-lg">
                    <div className="flex flex-col gap-0.5">
                      {/* Title with color chip */}
                      <div className="flex items-center gap-1">
                        <div
                          className="size-3 shrink-0 rounded"
                          style={{ backgroundColor: barColor }}
                        />
                        <p className="text-text-neutral-primary text-xs leading-5 font-medium">
                          {item.value.toLocaleString()}{" "}
                          {item.name === "Informational" ? "Info" : item.name}{" "}
                          {item.name === "Fail" || item.name === "Pass"
                            ? "Findings"
                            : "Risk"}
                        </p>
                      </div>

                      {/* New Findings row */}
                      {item.newFindings !== undefined && (
                        <div className="flex items-center gap-1">
                          <Bell
                            size={12}
                            className="text-text-neutral-secondary shrink-0"
                          />
                          <p className="text-text-neutral-secondary text-xs leading-5 font-medium">
                            {item.newFindings} New Findings
                          </p>
                        </div>
                      )}

                      {/* Change percentage row */}
                      {item.change !== undefined && (
                        <div className="flex items-start">
                          <p className="text-text-neutral-secondary text-xs leading-5 font-medium">
                            {item.change > 0 ? "+" : ""}
                            {item.change}% Since last scan
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Percentage and Count */}
              <div
                className="text-text-neutral-secondary ml-6 flex min-w-[90px] shrink-0 items-center gap-2 text-sm"
                style={{
                  opacity: isFaded ? 0.5 : 1,
                  transition: "opacity 0.2s",
                }}
              >
                <span className="min-w-[26px] text-right font-medium">
                  {displayPercentage}%
                </span>
                <span className="shrink-0 font-medium">•</span>
                <span className="font-bold whitespace-nowrap">
                  {isEmpty ? "0" : item.value.toLocaleString()}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
