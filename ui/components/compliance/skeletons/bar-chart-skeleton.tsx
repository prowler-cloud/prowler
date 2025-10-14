"use client";

import { Skeleton } from "@heroui/skeleton";

export const BarChartSkeleton = () => {
  return (
    <div className="flex w-[400px] flex-col items-center justify-between">
      {/* Title skeleton */}
      <Skeleton className="h-4 w-40 rounded-lg">
        <div className="bg-default-200 h-4" />
      </Skeleton>

      {/* Chart area skeleton */}
      <div className="ml-24 flex h-full flex-col justify-center gap-2 p-4">
        {/* Bar chart skeleton - 5 horizontal bars */}
        {Array.from({ length: 5 }).map((_, index) => (
          <div key={index} className="flex items-center gap-4">
            {/* Bar skeleton with varying widths */}
            <Skeleton
              className={`h-10 rounded-lg ${
                index === 0
                  ? "w-48"
                  : index === 1
                    ? "w-40"
                    : index === 2
                      ? "w-32"
                      : index === 3
                        ? "w-24"
                        : "w-16"
              }`}
            >
              <div className="bg-default-200 h-6" />
            </Skeleton>
          </div>
        ))}

        {/* Legend skeleton */}
        <div className="flex justify-center gap-4 pt-2">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={index} className="flex items-center gap-1">
              <Skeleton className="h-3 w-3 rounded-full">
                <div className="bg-default-200 h-3 w-3" />
              </Skeleton>
              <Skeleton className="h-3 w-16 rounded-lg">
                <div className="bg-default-200 h-3" />
              </Skeleton>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
