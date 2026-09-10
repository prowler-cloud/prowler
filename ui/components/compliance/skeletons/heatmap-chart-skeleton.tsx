"use client";

import { Skeleton } from "@/components/shadcn";

export const HeatmapChartSkeleton = () => {
  return (
    <div className="flex h-[320px] w-[400px] flex-col items-center justify-between lg:w-[400px]">
      {/* Title skeleton */}
      <Skeleton className="h-4 w-36 rounded-lg" />

      {/* Heatmap area skeleton - 3x3 grid like the real component */}
      <div className="h-full w-full p-4">
        <div className="grid h-full w-full grid-cols-3 gap-1">
          {Array.from({ length: 9 }).map((_, index) => (
            <Skeleton key={index} className="rounded border" />
          ))}
        </div>
      </div>
    </div>
  );
};
