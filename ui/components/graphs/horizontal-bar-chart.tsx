"use client";

import { Bell } from "lucide-react";
import { useState } from "react";

import { SEVERITY_ORDER } from "./shared/constants";
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
          <h3
            className="text-lg font-semibold"
            style={{ color: "var(--text-neutral-primary)" }}
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
            ? "var(--bg-neutral-tertiary)"
            : item.color ||
              getSeverityColorByName(item.name) ||
              "var(--bg-neutral-tertiary)";

          return (
            <div
              key={item.name}
              className="flex gap-6"
              onMouseEnter={() => !isEmpty && setHoveredIndex(index)}
              onMouseLeave={() => !isEmpty && setHoveredIndex(null)}
            >
              {/* Label */}
              <div className="w-20 shrink-0">
                <span
                  className="text-sm font-medium"
                  style={{
                    color: "var(--text-neutral-secondary)",
                    opacity: isFaded ? 0.5 : 1,
                    transition: "opacity 0.2s",
                  }}
                >
                  {item.name === "Informational" ? "Info" : item.name}
                </span>
              </div>

              {/* Bar - flexible */}
              <div className="relative flex-1">
                <div className="bg-bg-neutral-tertiary absolute inset-0 h-[22px] w-full rounded-sm" />
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
                          Risk
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
                className="flex w-[90px] shrink-0 items-center gap-2 text-sm"
                style={{
                  color: "var(--text-neutral-secondary)",
                  opacity: isFaded ? 0.5 : 1,
                  transition: "opacity 0.2s",
                }}
              >
                <span className="w-[26px] text-right font-medium">
                  {isEmpty ? "0" : item.percentage}%
                </span>
                <span
                  className="font-medium"
                  style={{ color: "var(--text-neutral-secondary)" }}
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
