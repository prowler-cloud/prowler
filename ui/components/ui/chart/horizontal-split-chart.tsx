"use client";

import { Tooltip } from "@nextui-org/react";
import * as React from "react";
import { useEffect } from "react";

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
   * @default "bg-system-success"
   */
  colorA?: string;
  /**
   * Color for value B (Tailwind classes)
   * @default "bg-system-error"
   */
  colorB?: string;
  /**
   * Value format suffix (like "%", "$", etc.)
   * Will be appended to the values when displayed
   * @example "%"
   */
  valueSuffix?: string;
  /**
   * Bar height
   * @default "h-6"
   */
  barHeight?: string;
  /**
   * Color for the empty state (when both values are 0)
   * @default "bg-gray-300"
   */
  emptyColor?: string;
  /**
   * Text to display when there is no data
   * @default "No data available"
   */
  emptyText?: string;
  /**
   * Minimum width for small values (in pixels)
   * @default 25
   */
  minBarWidth?: number;
  /**
   * Custom tooltip content for value A (optional)
   * If not provided, the formatted value will be used
   */
  tooltipContentA?: string;
  /**
   * Custom tooltip content for value B (optional)
   * If not provided, the formatted value will be used
   */
  tooltipContentB?: string;
  /**
   * Text color for labels
   * @default "text-gray-700"
   */
  labelColor?: string;
}

/**
 * Horizontal split bar chart component that displays two values
 * with bars growing from a central separator.
 *
 * @example
 * ```tsx
 * <HorizontalSplitBar
 *   valueA={54}
 *   valueB={38}
 *   valueSuffix="%"
 * />
 * ```
 */
export const HorizontalSplitBar = ({
  valueA,
  valueB,
  className,
  colorA = "bg-system-success",
  colorB = "bg-system-error",
  valueSuffix = "",
  barHeight = "h-6",
  emptyColor = "bg-gray-300",
  emptyText = "No data available",
  minBarWidth = 25,
  tooltipContentA,
  tooltipContentB,
  labelColor = "text-gray-700",
}: HorizontalSplitBarProps) => {
  // Reference to the container to measure its width
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [maxContainerWidth, setMaxContainerWidth] = React.useState(0);

  // Effect to measure the container width
  useEffect(() => {
    if (containerRef.current) {
      const updateWidth = () => {
        const containerWidth = containerRef.current?.clientWidth || 0;
        setMaxContainerWidth(containerWidth);
      };

      updateWidth();

      window.addEventListener("resize", updateWidth);
      return () => window.removeEventListener("resize", updateWidth);
    }
  }, []);

  // Ensure values are positive
  const valA = Math.max(0, valueA);
  const valB = Math.max(0, valueB);

  const hasNoData = valA === 0 && valB === 0;
  const formattedValueA = `${valA}${valueSuffix}`;
  const formattedValueB = `${valB}${valueSuffix}`;

  if (hasNoData) {
    return (
      <div ref={containerRef} className={cn("flex w-full flex-col", className)}>
        <div className="flex w-full justify-center">
          <div
            className={cn(
              `w-full ${barHeight} flex items-center justify-center rounded-full`,
              emptyColor,
            )}
          >
            <span className="text-xs font-medium text-gray-600">
              {emptyText}
            </span>
          </div>
        </div>
      </div>
    );
  }

  const availableWidth = Math.max(0, maxContainerWidth);
  const halfWidth = availableWidth / 2;
  const separatorWidth = 1;

  let rawWidthA = valA;
  let rawWidthB = valB;

  // Determine if we need to scale to fit in available space
  const maxSideWidth = halfWidth - separatorWidth / 2;
  const needsScaling = rawWidthA > maxSideWidth || rawWidthB > maxSideWidth;

  if (needsScaling) {
    // Calculate scale factor based on the largest value
    const maxRawWidth = Math.max(rawWidthA, rawWidthB);
    const scaleFactor = maxSideWidth / maxRawWidth;

    // Apply the scale factor to both sides
    rawWidthA = rawWidthA * scaleFactor;
    rawWidthB = rawWidthB * scaleFactor;
  }

  // Apply minimum width if needed
  const barWidthA = Math.max(rawWidthA, valA > 0 ? minBarWidth : 0);
  const barWidthB = Math.max(rawWidthB, valB > 0 ? minBarWidth : 0);

  return (
    <div ref={containerRef} className={cn("flex w-full flex-col", className)}>
      <div className="flex items-center justify-center">
        <div
          className="flex items-center justify-end gap-2"
          style={{ width: `${halfWidth}px` }}
        >
          {/* Left label */}
          <div className={cn("text-xs font-medium", labelColor)}>
            {valA > 0 ? formattedValueA : "0"}
          </div>
          {/* Left bar */}
          {valA > 0 && (
            <Tooltip
              content={`${formattedValueA} ${tooltipContentA ? tooltipContentA : ""}`}
              className="text-xs"
            >
              <div
                className={cn(`${barHeight} rounded-l-full`, colorA)}
                style={{
                  width: `${barWidthA}px`,
                }}
              />
            </Tooltip>
          )}
        </div>

        {/* Central separator */}
        <div
          className="flex-shrink-0 bg-background"
          style={{ width: `${separatorWidth}px` }}
        />

        <div
          className="flex items-center justify-start gap-2"
          style={{ width: `${halfWidth}px` }}
        >
          {/* Right bar */}
          {valB > 0 && (
            <Tooltip
              content={`${formattedValueB} ${tooltipContentB ? tooltipContentB : ""}`}
              className="text-xs"
            >
              <div
                className={cn(`${barHeight} rounded-r-full`, colorB)}
                style={{
                  width: `${barWidthB}px`,
                }}
              />
            </Tooltip>
          )}
          {/* Right label */}
          <div className={cn("text-xs font-medium", labelColor)}>
            {valB > 0 ? formattedValueB : "0"}
          </div>
        </div>
      </div>
    </div>
  );
};

// Assign a displayName for DevTools
HorizontalSplitBar.displayName = "HorizontalSplitBar";

export default HorizontalSplitBar;
