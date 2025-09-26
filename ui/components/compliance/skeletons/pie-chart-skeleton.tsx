"use client";

import { Skeleton } from "@heroui/skeleton";

export const PieChartSkeleton = () => {
  return (
    <div className="flex h-[320px] flex-col items-center justify-between">
      {/* Title skeleton */}
      <Skeleton className="h-4 w-32 rounded-lg">
        <div className="bg-default-200 h-4" />
      </Skeleton>

      {/* Pie chart skeleton */}
      <div className="relative flex aspect-square w-[200px] min-w-[200px] items-center justify-center">
        {/* Outer circle */}
        <Skeleton className="absolute h-[200px] w-[200px] rounded-full">
          <div className="bg-default-200 h-[200px] w-[200px]" />
        </Skeleton>

        {/* Inner circle (donut hole) */}
        <div className="bg-background absolute h-[140px] w-[140px] rounded-full"></div>

        {/* Center text skeleton */}
        <div className="absolute flex flex-col items-center">
          <Skeleton className="h-6 w-8 rounded-lg">
            <div className="bg-default-300 h-6" />
          </Skeleton>
          <Skeleton className="mt-1 h-3 w-6 rounded-lg">
            <div className="bg-default-300 h-3" />
          </Skeleton>
        </div>
      </div>

      {/* Bottom stats skeleton */}
      <div className="mt-2 grid grid-cols-3 gap-4">
        <div className="flex flex-col items-center">
          <Skeleton className="h-4 w-8 rounded-lg">
            <div className="bg-default-200 h-4" />
          </Skeleton>
          <Skeleton className="mt-1 h-5 w-6 rounded-lg">
            <div className="bg-default-200 h-5" />
          </Skeleton>
        </div>
        <div className="flex flex-col items-center">
          <Skeleton className="h-4 w-6 rounded-lg">
            <div className="bg-default-200 h-4" />
          </Skeleton>
          <Skeleton className="mt-1 h-5 w-6 rounded-lg">
            <div className="bg-default-200 h-5" />
          </Skeleton>
        </div>
        <div className="flex flex-col items-center">
          <Skeleton className="h-4 w-12 rounded-lg">
            <div className="bg-default-200 h-4" />
          </Skeleton>
          <Skeleton className="mt-1 h-5 w-6 rounded-lg">
            <div className="bg-default-200 h-5" />
          </Skeleton>
        </div>
      </div>
    </div>
  );
};
