"use client";

import { Spinner } from "@/components/shadcn/spinner/spinner";

/**
 * Loading skeleton for graph visualization
 * Shows while graph data is being fetched and processed
 */
export const GraphLoading = () => {
  return (
    <div
      data-testid="graph-loading"
      className="flex min-h-[320px] flex-col items-center justify-center gap-4 text-center"
    >
      <Spinner className="size-6" />
      <p className="text-muted-foreground text-sm">
        Loading Attack Paths graph...
      </p>
    </div>
  );
};
