"use client";

import { Spinner } from "@heroui/spinner";

/**
 * Loading skeleton for graph visualization
 * Shows while graph data is being fetched and processed
 */
export const GraphLoading = () => {
  return (
    <div className="dark:bg-prowler-blue-400 flex h-96 items-center justify-center rounded-lg bg-gray-50">
      <div className="flex flex-col items-center gap-3">
        <Spinner size="lg" color="primary" />
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Loading attack path graph...
        </p>
      </div>
    </div>
  );
};
