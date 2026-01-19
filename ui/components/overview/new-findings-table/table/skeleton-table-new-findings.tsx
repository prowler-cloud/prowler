import React from "react";

import { Card } from "@/components/shadcn/card/card";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

export const SkeletonTableNewFindings = () => {
  const columns = 7;
  const rows = 3;

  return (
    <Card variant="base" padding="md" className="flex flex-col gap-4">
      {/* Table headers */}
      <div className="flex gap-4">
        {Array.from({ length: columns }).map((_, index) => (
          <Skeleton
            key={`header-${index}`}
            className="h-8"
            style={{ width: `${100 / columns}%` }}
          />
        ))}
      </div>

      {/* Table body */}
      <div className="flex flex-col gap-3">
        {Array.from({ length: rows }).map((_, rowIndex) => (
          <div key={`row-${rowIndex}`} className="flex gap-4">
            {Array.from({ length: columns }).map((_, colIndex) => (
              <Skeleton
                key={`cell-${rowIndex}-${colIndex}`}
                className="h-12"
                style={{ width: `${100 / columns}%` }}
              />
            ))}
          </div>
        ))}
      </div>
    </Card>
  );
};
