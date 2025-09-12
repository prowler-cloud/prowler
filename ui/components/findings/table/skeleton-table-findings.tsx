import React from "react";

import { SkeletonTable } from "../../ui/skeleton/skeleton";

export const SkeletonTableFindings = () => {
  return (
    <div className="bg-card rounded-xl border p-4 shadow-sm">
      <SkeletonTable rows={4} columns={7} />
    </div>
  );
};
