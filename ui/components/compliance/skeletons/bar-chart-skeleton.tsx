"use client";

import { Skeleton } from "@nextui-org/react";

export const BarChartSkeleton = () => {
  return (
    <div className="flex w-[400px] flex-col items-center justify-between">
      {/* Title skeleton */}
      <Skeleton className="h-4 w-40 rounded-lg">
        <div className="h-4 bg-default-200" />
      </Skeleton>

      {/* Chart area skeleton */}
      <div className="ml-24 flex h-full flex-col justify-center space-y-2 p-4">
        {/* Bar chart skeleton - 5 horizontal bars */}
        {Array.from({ length: 5 }).map((_, index) => (
          <div key={index} className="flex items-center space-x-4">
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
              <div className="h-6 bg-default-200" />
            </Skeleton>
          </div>
        ))}

        {/* Legend skeleton */}
        <div className="flex justify-center space-x-4 pt-2">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={index} className="flex items-center space-x-1">
              <Skeleton className="h-3 w-3 rounded-full">
                <div className="h-3 w-3 bg-default-200" />
              </Skeleton>
              <Skeleton className="h-3 w-16 rounded-lg">
                <div className="h-3 bg-default-200" />
              </Skeleton>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
