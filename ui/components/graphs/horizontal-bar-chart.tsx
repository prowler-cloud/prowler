"use client";

import { Bell } from "lucide-react";
import { useState } from "react";

import { CHART_COLORS, SEVERITY_ORDER } from "./shared/constants";
import { getSeverityColorByName } from "./shared/utils";
import { BarDataPoint } from "./types";

interface HorizontalBarChartProps {
  data: BarDataPoint[];
  height?: number;
  title?: string;
}

export function HorizontalBarChart({ data, title }: HorizontalBarChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const total = data.reduce((sum, d) => sum + (Number(d.value) || 0), 0);
  const isEmpty = total <= 0;

  const emptyData: BarDataPoint[] = [
    { name: "Critical", value: 1, percentage: 100 },
    { name: "High", value: 1, percentage: 100 },
    { name: "Medium", value: 1, percentage: 100 },
    { name: "Low", value: 1, percentage: 100 },
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
          <h3
            className="text-lg font-semibold"
            style={{ color: "var(--chart-text-primary)" }}
          >
            {title}
          </h3>
        </div>
      )}

      <div className="space-y-6">
        {sortedData.map((item, index) => {
          const isHovered = !isEmpty && hoveredIndex === index;
          const isFaded = !isEmpty && hoveredIndex !== null && !isHovered;
          const barColor = isEmpty
            ? CHART_COLORS.gridLine
            : item.color ||
              getSeverityColorByName(item.name) ||
              CHART_COLORS.defaultColor;

          return (
            <div
              key={index}
              className="flex items-center gap-6"
              onMouseEnter={() => !isEmpty && setHoveredIndex(index)}
              onMouseLeave={() => !isEmpty && setHoveredIndex(null)}
            >
              {/* Label */}
              <div className="w-20 shrink-0">
                <span
                  className="text-sm font-medium"
                  style={{
                    color: "var(--chart-text-primary)",
                    opacity: isFaded ? 0.5 : 1,
                    transition: "opacity 0.2s",
                  }}
                >
                  {item.name}
                </span>
              </div>

              {/* Bar - flexible */}
              <div className="relative flex-1">
                <div className="absolute inset-0 h-[22px] w-full rounded-sm bg-[#FAFAFA] dark:bg-black" />
                {(item.value > 0 || isEmpty) && (
                  <div
                    className="relative h-[22px] rounded-sm border border-black/10 transition-all duration-300"
                    style={{
                      width: isEmpty
                        ? `${item.percentage}%`
                        : `${item.percentage || (item.value / Math.max(...data.map((d) => d.value))) * 100}%`,
                      backgroundColor: barColor,
                      opacity: isFaded ? 0.5 : 1,
                    }}
                  />
                )}

                {isHovered && (
                  <div className="absolute top-10 left-0 z-10 rounded-xl border border-slate-200 bg-white px-3 py-1.5 shadow-lg dark:border-[#202020] dark:bg-[#121110]">
                    <div className="flex flex-col gap-0.5">
                      {/* Title with color chip */}
                      <div className="flex items-center gap-1">
                        <div
                          className="size-3 shrink-0 rounded"
                          style={{ backgroundColor: barColor }}
                        />
                        <p className="text-sm leading-5 font-medium text-slate-900 dark:text-[#f4f4f5]">
                          {item.value.toLocaleString()} {item.name} Risk
                        </p>
                      </div>

                      {/* New Findings row */}
                      {item.newFindings !== undefined && (
                        <div className="flex items-center gap-1">
                          <Bell
                            size={12}
                            className="shrink-0 text-slate-600 dark:text-[#d4d4d8]"
                          />
                          <p className="text-sm leading-5 font-medium text-slate-600 dark:text-[#d4d4d8]">
                            {item.newFindings} New Findings
                          </p>
                        </div>
                      )}

                      {/* Change percentage row */}
                      {item.change !== undefined && (
                        <div className="flex items-start">
                          <p className="text-sm leading-5 font-medium text-slate-600 dark:text-[#d4d4d8]">
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
                className="flex w-[90px] shrink-0 items-center gap-2 text-sm"
                style={{
                  color: "var(--chart-text-primary)",
                  opacity: isFaded ? 0.5 : 1,
                  transition: "opacity 0.2s",
                }}
              >
                <span className="w-[26px] text-right font-medium">
                  {isEmpty ? "0" : item.percentage}%
                </span>
                <span
                  className="font-medium"
                  style={{ color: "var(--chart-text-secondary)" }}
                >
                  •
                </span>
                <span className="font-bold">
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
