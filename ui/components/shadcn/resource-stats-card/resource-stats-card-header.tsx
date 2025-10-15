import { LucideIcon } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/utils";

export interface ResourceStatsCardHeaderProps
  extends React.HTMLAttributes<HTMLDivElement> {
  icon: LucideIcon;
  title: string;
  resourceCount?: number | string;
  size?: "sm" | "md" | "lg";
}

const sizeStyles = {
  sm: {
    icon: "h-3.5 w-3.5",
    title: "text-sm",
    count: "text-[9px]",
  },
  md: {
    icon: "h-4 w-4",
    title: "text-base",
    count: "text-[10px]",
  },
  lg: {
    icon: "h-5 w-5",
    title: "text-lg",
    count: "text-xs",
  },
};

export const ResourceStatsCardHeader = React.forwardRef<
  HTMLDivElement,
  ResourceStatsCardHeaderProps
>(
  (
    { icon: Icon, title, resourceCount, size = "md", className, ...props },
    ref,
  ) => {
    const styles = sizeStyles[size];

    return (
      <div
        ref={ref}
        className={cn("flex w-full items-center gap-1", className)}
        {...props}
      >
        <div className="flex flex-1 items-center gap-1">
          <Icon
            className={cn("text-zinc-300 dark:text-zinc-300", styles.icon)}
            strokeWidth={2}
          />
          <span
            className={cn(
              "leading-7 font-semibold text-zinc-300 dark:text-zinc-300",
              styles.title,
            )}
          >
            {title}
          </span>
        </div>
        {resourceCount !== undefined && (
          <span
            className={cn(
              "leading-4 font-normal text-zinc-400 dark:text-zinc-400",
              styles.count,
            )}
          >
            {typeof resourceCount === "number"
              ? `${resourceCount} Resources`
              : resourceCount}
          </span>
        )}
      </div>
    );
  },
);

ResourceStatsCardHeader.displayName = "ResourceStatsCardHeader";
