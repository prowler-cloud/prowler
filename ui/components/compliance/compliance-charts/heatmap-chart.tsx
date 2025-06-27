"use client";

import { cn } from "@nextui-org/react";
import { useTheme } from "next-themes";
import { useState } from "react";

import { CategoryData } from "@/types/compliance";

interface HeatmapChartProps {
  categories?: CategoryData[];
}

const getHeatmapColor = (percentage: number): string => {
  if (percentage === 0) return "#3CEC6D";
  if (percentage <= 25) return "#fcd34d";
  if (percentage <= 50) return "#FA7315";
  if (percentage <= 100) return "#F31260";
  return "#F31260";
};
const capitalizeFirstLetter = (text: string): string => {
  const lowerText = text.toLowerCase();
  const firstLetterIndex = lowerText.search(/[a-zA-Z]/);
  if (firstLetterIndex === -1) return text; // No letters found

  return (
    lowerText.slice(0, firstLetterIndex) +
    lowerText.charAt(firstLetterIndex).toUpperCase() +
    lowerText.slice(firstLetterIndex + 1)
  );
};

const title = (
  <h3 className="mb-2 whitespace-nowrap text-xs font-semibold uppercase tracking-wide">
    Sections Failure Rate
  </h3>
);

export const HeatmapChart = ({ categories = [] }: HeatmapChartProps) => {
  const { theme } = useTheme();
  const [hoveredItem, setHoveredItem] = useState<CategoryData | null>(null);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  // Use categories data and prepare it
  const heatmapData = categories
    .filter((item) => item.totalRequirements > 0)
    .sort((a, b) => b.failurePercentage - a.failurePercentage)
    .slice(0, 9); // Exactly 9 items for 3x3 grid

  // Check if there are no items with data
  if (!categories.length || heatmapData.length === 0) {
    return (
      <div className="flex w-[400px] flex-col items-center justify-between lg:w-[400px]">
        {title}
        <div className="flex h-[320px] w-full items-center justify-center">
          <p className="text-sm text-gray-500">No category data available</p>
        </div>
      </div>
    );
  }

  const handleMouseEnter = (item: CategoryData, event: React.MouseEvent) => {
    setHoveredItem(item);
    setMousePosition({ x: event.clientX, y: event.clientY });
  };

  const handleMouseMove = (event: React.MouseEvent) => {
    setMousePosition({ x: event.clientX, y: event.clientY });
  };

  const handleMouseLeave = () => {
    setHoveredItem(null);
  };

  return (
    <div className="flex h-[320px] w-[400px] flex-col items-center justify-between lg:w-[400px]">
      {title}

      <div className="h-full w-full p-2">
        <div
          className={cn(
            "grid h-full w-full gap-1",
            heatmapData.length < 3 ? "grid-cols-1" : "grid-cols-3",
          )}
          style={{
            gridTemplateRows:
              heatmapData.length < 3
                ? `repeat(${heatmapData.length}, ${heatmapData.length}fr)`
                : `repeat(${Math.min(Math.ceil(heatmapData.length / 3), 3)}, 1fr)`,
          }}
        >
          {heatmapData.map((item) => (
            <div
              key={item.name}
              className="flex items-center justify-center rounded border p-1"
              style={{
                backgroundColor: getHeatmapColor(item.failurePercentage),
                borderColor: theme === "dark" ? "#374151" : "#e5e7eb",
              }}
              onMouseEnter={(e) => handleMouseEnter(item, e)}
              onMouseMove={handleMouseMove}
              onMouseLeave={handleMouseLeave}
            >
              <div className="w-full px-1 text-center antialiased">
                <div
                  className="truncate text-xs font-semibold"
                  style={{
                    color: theme === "dark" ? "#ffffff" : "#000000",
                  }}
                  title={capitalizeFirstLetter(item.name)}
                >
                  {capitalizeFirstLetter(item.name)}
                </div>
                <div
                  className="text-xs"
                  style={{
                    color: theme === "dark" ? "#ffffff" : "#000000",
                  }}
                >
                  {item.failurePercentage}%
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Custom Tooltip */}
        {hoveredItem && (
          <div
            className="pointer-events-none fixed z-50 rounded border px-3 py-2 text-xs shadow-lg"
            style={{
              left: mousePosition.x + 10,
              top: mousePosition.y - 10,
              backgroundColor: theme === "dark" ? "#1e293b" : "white",
              borderColor: theme === "dark" ? "#475569" : "rgba(0, 0, 0, 0.1)",
              color: theme === "dark" ? "white" : "black",
            }}
          >
            <div className="mb-1 font-semibold">
              {capitalizeFirstLetter(hoveredItem.name)}
            </div>
            <div>Failure Rate: {hoveredItem.failurePercentage}%</div>
            <div>
              Failed: {hoveredItem.failedRequirements}/
              {hoveredItem.totalRequirements}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
