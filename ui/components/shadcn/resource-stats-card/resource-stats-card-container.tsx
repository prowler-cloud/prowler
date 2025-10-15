import * as React from "react";

import { cn } from "@/lib/utils";

export interface ResourceStatsCardContainerProps
  extends React.HTMLAttributes<HTMLDivElement> {}

export const ResourceStatsCardContainer = React.forwardRef<
  HTMLDivElement,
  ResourceStatsCardContainerProps
>(({ className, children, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn(
        "flex rounded-xl border border-[rgba(38,38,38,0.7)] bg-[rgba(23,23,23,0.5)] px-[19px] py-[9px] backdrop-blur-[46px]",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
});

ResourceStatsCardContainer.displayName = "ResourceStatsCardContainer";
