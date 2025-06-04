import React from "react";

import { SkeletonTable } from "@/components/ui/skeleton/skeleton";

export const SkeletonTableNewFindings = () => {
  return (
    <div className="bg-card rounded-xl border p-4 shadow-sm">
      <SkeletonTable rows={3} columns={7} />
    </div>
  );
};
