"use client";

import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

/**
 * Loading skeleton for graph visualization
 * Shows while graph data is being fetched and processed
 */
export const GraphLoading = () => {
  return (
    <div className="dark:bg-prowler-blue-400 flex h-96 items-center justify-center rounded-lg bg-gray-50">
      <div className="flex flex-col items-center gap-3">
        <div className="flex gap-2">
          <Skeleton className="h-3 w-3 rounded-full" />
          <Skeleton className="h-3 w-3 rounded-full" />
          <Skeleton className="h-3 w-3 rounded-full" />
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Loading Attack Paths graph...
        </p>
      </div>
    </div>
  );
};
