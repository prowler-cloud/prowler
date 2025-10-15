import * as React from "react";

import { cn } from "@/lib/utils";

export interface ResourceStatsCardDividerProps
  extends React.HTMLAttributes<HTMLDivElement> {}

export const ResourceStatsCardDivider = React.forwardRef<
  HTMLDivElement,
  ResourceStatsCardDividerProps
>(({ className, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn("flex items-center justify-center px-[23px]", className)}
      {...props}
    >
      <div
        className="h-full w-px"
        style={{ backgroundColor: "rgba(39, 39, 42, 1)" }}
      />
    </div>
  );
});

ResourceStatsCardDivider.displayName = "ResourceStatsCardDivider";
