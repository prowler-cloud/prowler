"use client";

import { useState } from "react";
import { useTheme } from "next-themes";
import { CategoryData, RegionData } from "@/types/compliance";

interface HeatmapChartProps {
  regions: RegionData[];
  categories?: CategoryData[];
  isRegionFiltered?: boolean; // Indicates if a region filter is active
  filteredRegionName?: string; // Name of the filtered region
}

const getHeatmapColor = (percentage: number): string => {
  if (percentage === 0) return "#10b981"; // Green for 0% failures
  if (percentage <= 25) return "#eab308"; // Yellow
  if (percentage <= 50) return "#f97316"; // Orange
  if (percentage <= 100) return "#ef4444"; // Red
  return "#ef4444";
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

const getTitle = (isRegionFiltered: boolean, regionName?: string) => (
  <h3 className="whitespace-nowrap text-xs font-semibold uppercase tracking-wide">
    {isRegionFiltered ? "Categories Failure Rate" : "Failure Rate by Region"}
  </h3>
);

export const HeatmapChart = ({
  regions,
  categories = [],
  isRegionFiltered = false,
  filteredRegionName,
}: HeatmapChartProps) => {
  const { theme } = useTheme();
  const [hoveredItem, setHoveredItem] = useState<
    RegionData | CategoryData | null
  >(null);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  // Determine what data to show and prepare it
  const dataToShow = isRegionFiltered ? categories : regions;
  const heatmapData = dataToShow
    .filter((item) => item.totalRequirements > 0)
    .sort((a, b) => b.failurePercentage - a.failurePercentage)
    .slice(0, 9); // Exactly 9 items for 3x3 grid

  // Check if there are no items with data
  if (!dataToShow || dataToShow.length === 0 || heatmapData.length === 0) {
    const noDataMessage = isRegionFiltered
      ? "No category data available"
      : "No regional data available";

    return (
      <div className="flex w-[400px] flex-col items-center justify-between lg:w-[400px]">
        {getTitle(isRegionFiltered, filteredRegionName)}
        <div className="flex h-[320px] w-full items-center justify-center">
          <p className="text-sm text-gray-500">{noDataMessage}</p>
        </div>
      </div>
    );
  }

  const handleMouseEnter = (
    item: RegionData | CategoryData,
    event: React.MouseEvent,
  ) => {
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
      <div>{getTitle(isRegionFiltered, filteredRegionName)}</div>

      <div className="h-full w-full p-4">
        {/* 3x3 Grid */}
        <div className="grid h-full w-full grid-cols-3 gap-1">
          {heatmapData.map((item, index) => (
            <div
              key={item.name}
              className="flex items-center justify-center rounded border"
              style={{
                backgroundColor: getHeatmapColor(item.failurePercentage),
                borderColor: theme === "dark" ? "#374151" : "#e5e7eb",
              }}
              onMouseEnter={(e) => handleMouseEnter(item, e)}
              onMouseMove={handleMouseMove}
              onMouseLeave={handleMouseLeave}
            >
              <div className="text-center">
                <div
                  className="text-xs font-semibold"
                  style={{
                    color: theme === "dark" ? "#ffffff" : "#000000",
                  }}
                >
                  {isRegionFiltered
                    ? capitalizeFirstLetter(item.name)
                    : item.name}
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
              {isRegionFiltered
                ? capitalizeFirstLetter(hoveredItem.name)
                : hoveredItem.name}
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
