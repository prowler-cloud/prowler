"use client";

import { Tooltip } from "@nextui-org/react";
import * as React from "react";

import { cn } from "@/lib/utils";

interface HorizontalSplitBarProps {
  /**
   * First value (left)
   */
  valueA: number;
  /**
   * Second value (right)
   */
  valueB: number;
  /**
   * Additional CSS classes for the main container
   */
  className?: string;
  /**
   * Color for value A (Tailwind classes)
   * @default "bg-action"
   */
  colorA?: string;
  /**
   * Color for value B (Tailwind classes)
   * @default "bg-danger"
   */
  colorB?: string;
  /**
   * Tooltip for value A
   * @default "Passed checks"
   */
  tooltipA?: string;
  /**
   * Tooltip for value B
   * @default "Failed checks"
   */
  tooltipB?: string;
  /**
   * Bar height
   * @default "h-6"
   */
  barHeight?: string;
  /**
   * Color for empty state (when both values are 0)
   * @default "bg-gray-300"
   */
  emptyColor?: string;
  /**
   * Text to show when there's no data
   * @default "No data available"
   */
  emptyText?: string;
}

/**
 * Component of a horizontal bar chart that shows two values in a divided bar
 * with different colors for each value (by default, green for approved and red for failed).
 *
 * @example
 * ```tsx
 * <HorizontalSplitBar
 *   valueA={54}
 *   valueB={38}
 * />
 * ```
 */
export const HorizontalSplitBar = ({
  valueA,
  valueB,
  className,
  colorA = "bg-action",
  colorB = "bg-danger",
  tooltipA = "Passed checks",
  tooltipB = "Failed checks",
  barHeight = "h-6",
  emptyColor = "bg-gray-300",
  emptyText = "No data available",
}: HorizontalSplitBarProps) => {
  // Make sure values are positive
  const valA = Math.max(0, valueA);
  const valB = Math.max(0, valueB);

  // Calculate total and percentages
  const total = valA + valB;
  const percentageA = total > 0 ? (valA / total) * 100 : 0;

  // Check if there's no data
  const hasNoData = valA === 0 && valB === 0;

  return (
    <div className={cn("flex w-full flex-col gap-1", className)}>
      <div
        className={`relative w-full overflow-hidden rounded-full ${barHeight}`}
      >
        {hasNoData ? (
          <div
            className={cn(
              "flex h-full w-full items-center justify-center",
              emptyColor,
            )}
          >
            <span className="text-xs font-medium text-gray-600">
              {emptyText}
            </span>
          </div>
        ) : (
          <div className="relative flex h-full w-full gap-[1px] bg-white">
            {/* A bar (left) with minimum width for small values */}
            {valA > 0 && (
              <Tooltip content={`${valA} ${tooltipA}`} className="text-xs">
                <div
                  className={cn("flex h-full items-center pl-2", colorA)}
                  style={{
                    width: `${percentageA}%`,
                    minWidth: valB > 0 ? "40px" : "0",
                  }}
                >
                  <span className="ml-1 truncate text-xs font-semibold text-white">
                    {valA}
                  </span>
                </div>
              </Tooltip>
            )}

            {/* B bar (right) with minimum width for small values */}
            {valB > 0 && (
              <Tooltip content={`${valB} ${tooltipB}`} className="text-xs">
                <div
                  className={cn(
                    "flex h-full items-center justify-end pr-2",
                    colorB,
                  )}
                  style={{
                    width:
                      valA > 0 ? `calc(${100 - percentageA}% - 1px)` : "100%",
                    minWidth: valA > 0 ? "40px" : "0",
                  }}
                >
                  <span className="mr-1 truncate text-xs font-semibold text-white">
                    {valB}
                  </span>
                </div>
              </Tooltip>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default HorizontalSplitBar;
