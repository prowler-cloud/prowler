"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { RadarChart } from "@/components/graphs/radar-chart";
import type { BarDataPoint, RadarDataPoint } from "@/components/graphs/types";
import { Card } from "@/components/shadcn/card/card";
import { SEVERITY_FILTER_MAP } from "@/types/severities";

import { CategorySelector } from "./category-selector";

interface RiskRadarViewClientProps {
  data: RadarDataPoint[];
}

export function RiskRadarViewClient({ data }: RiskRadarViewClientProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [selectedPoint, setSelectedPoint] = useState<RadarDataPoint | null>(
    null,
  );

  const handleSelectPoint = (point: RadarDataPoint | null) => {
    setSelectedPoint(point);
  };

  const handleCategoryChange = (categoryId: string | null) => {
    if (categoryId === null) {
      setSelectedPoint(null);
    } else {
      const point = data.find((d) => d.categoryId === categoryId);
      setSelectedPoint(point ?? null);
    }
  };

  const handleBarClick = (dataPoint: BarDataPoint) => {
    if (!selectedPoint) return;

    // Build the URL with current filters
    const params = new URLSearchParams(searchParams.toString());

    // Add severity filter
    const severity = SEVERITY_FILTER_MAP[dataPoint.name];
    if (severity) {
      params.set("filter[severity__in]", severity);
    }

    // Add category filter for the selected point
    params.set("filter[category__in]", selectedPoint.categoryId);

    // Add exclude muted findings filter
    params.set("filter[muted]", "false");

    // Filter by FAIL findings
    params.set("filter[status__in]", "FAIL");

    // Navigate to findings page
    router.push(`/findings?${params.toString()}`);
  };

  return (
    <div className="flex h-full w-full flex-col gap-4">
      <div className="flex flex-1 gap-12 overflow-hidden">
        {/* Radar Section */}
        <div className="flex basis-[70%] flex-col overflow-hidden">
          <Card variant="base" className="flex flex-1 flex-col overflow-hidden">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-neutral-primary text-lg font-semibold">
                Risk Radar
              </h3>
              <CategorySelector
                categories={data}
                selectedCategory={selectedPoint?.categoryId ?? null}
                onCategoryChange={handleCategoryChange}
              />
            </div>

            <div className="relative min-h-[400px] w-full flex-1">
              <RadarChart
                data={data}
                height={400}
                selectedPoint={selectedPoint}
                onSelectPoint={handleSelectPoint}
              />
            </div>
          </Card>
        </div>

        {/* Details Section - No Card */}
        <div className="flex basis-[30%] items-center overflow-hidden">
          {selectedPoint && selectedPoint.severityData ? (
            <div className="flex w-full flex-col">
              <div className="mb-4">
                <h4 className="text-neutral-primary text-base font-semibold">
                  {selectedPoint.category}
                </h4>
                <p className="text-neutral-tertiary text-xs">
                  {selectedPoint.value} Total Findings
                </p>
              </div>
              <HorizontalBarChart
                data={selectedPoint.severityData}
                onBarClick={handleBarClick}
              />
            </div>
          ) : (
            <div className="flex w-full items-center justify-center text-center">
              <p className="text-neutral-tertiary text-sm">
                Select a category on the radar to view details
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
