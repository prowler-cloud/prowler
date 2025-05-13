import { Skeleton } from "@nextui-org/react";
import React from "react";

interface SkeletonAccordionProps {
  itemCount?: number;
  className?: string;
  isCompact?: boolean;
}

export const SkeletonAccordion = ({
  itemCount = 3,
  className = "",
  isCompact = false,
}: SkeletonAccordionProps) => {
  const itemHeight = isCompact ? "h-10" : "h-14";

  return (
    <div
      className={`w-full space-y-2 ${className} rounded-xl border border-gray-300 p-2 dark:border-gray-700`}
    >
      {[...Array(itemCount)].map((_, index) => (
        <Skeleton key={index} className="rounded-lg">
          <div className={`${itemHeight} bg-default-300`}></div>
        </Skeleton>
      ))}
    </div>
  );
};

SkeletonAccordion.displayName = "SkeletonAccordion";
