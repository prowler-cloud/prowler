import { LucideIcon } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/utils";

import { ResourceStatsCardContainer } from "./resource-stats-card-container";
import type { StatItem } from "./resource-stats-card-content";
import { ResourceStatsCardContent } from "./resource-stats-card-content";
import { ResourceStatsCardHeader } from "./resource-stats-card-header";

export type { StatItem };

// Variant styles for the container
const variantStyles = {
  default: "",
  fail: "border-[rgba(67,34,50,0.5)] bg-[rgba(67,34,50,0.2)] dark:border-[rgba(67,34,50,0.7)] dark:bg-[rgba(67,34,50,0.3)]",
  pass: "border-[rgba(32,66,55,0.5)] bg-[rgba(32,66,55,0.2)] dark:border-[rgba(32,66,55,0.7)] dark:bg-[rgba(32,66,55,0.3)]",
  warning:
    "border-[rgba(61,53,32,0.5)] bg-[rgba(61,53,32,0.2)] dark:border-[rgba(61,53,32,0.7)] dark:bg-[rgba(61,53,32,0.3)]",
  info: "border-[rgba(30,58,95,0.5)] bg-[rgba(30,58,95,0.2)] dark:border-[rgba(30,58,95,0.7)] dark:bg-[rgba(30,58,95,0.3)]",
} as const;

// Size styles for the container
const sizeStyles = {
  sm: "px-2 py-1.5 gap-1",
  md: "px-3 py-2 gap-2",
  lg: "px-4 py-3 gap-3",
} as const;

export interface ResourceStatsCardProps
  extends Omit<React.HTMLAttributes<HTMLDivElement>, "color"> {
  // Optional header (icon + title + resource count)
  header?: {
    icon: LucideIcon;
    title: string;
    resourceCount?: number | string;
  };

  // Empty state message (when there's no data to display)
  emptyState?: {
    message: string;
  };

  // Main badge (top section) - optional when using empty state
  badge?: {
    icon: LucideIcon;
    count: number | string;
    variant?: "fail" | "pass" | "warning" | "info";
  };

  // Main label - optional when using empty state
  label?: string;

  // Vertical accent line color (optional, auto-determined from variant)
  accentColor?: string;

  // Sub-statistics array (flexible items)
  stats?: StatItem[];

  // Visual variant for the container background/border
  variant?: "default" | "fail" | "pass" | "warning" | "info";

  // Size variant
  size?: "sm" | "md" | "lg";

  // Render without container (no border, background, padding) - useful for composing multiple cards in a custom container
  containerless?: boolean;
}

export const ResourceStatsCard = React.forwardRef<
  HTMLDivElement,
  ResourceStatsCardProps
>(
  (
    {
      header,
      emptyState,
      badge,
      label,
      accentColor,
      stats = [],
      variant = "default",
      size = "md",
      containerless = false,
      className,
      ...props
    },
    ref,
  ) => {
    // If containerless, render without outer wrapper
    if (containerless) {
      return (
        <div
          ref={ref}
          className={cn("flex flex-col gap-[5px]", className)}
          {...props}
        >
          {header && <ResourceStatsCardHeader {...header} size={size} />}
          {emptyState ? (
            <div className="flex h-[51px] w-full flex-col items-center justify-center">
              <p className="text-center text-sm leading-5 font-medium text-zinc-600 dark:text-zinc-600">
                {emptyState.message}
              </p>
            </div>
          ) : (
            badge &&
            label && (
              <ResourceStatsCardContent
                badge={badge}
                label={label}
                stats={stats}
                accentColor={accentColor}
                size={size}
              />
            )
          )}
        </div>
      );
    }

    // Otherwise, render with container
    return (
      <ResourceStatsCardContainer
        ref={ref}
        className={cn(
          variantStyles[variant],
          sizeStyles[size],
          "flex-col",
          className,
        )}
        {...props}
      >
        {header && <ResourceStatsCardHeader {...header} size={size} />}
        {emptyState ? (
          <div className="flex h-[51px] w-full flex-col items-center justify-center">
            <p className="text-center text-sm leading-5 font-medium text-zinc-600 dark:text-zinc-600">
              {emptyState.message}
            </p>
          </div>
        ) : (
          badge &&
          label && (
            <ResourceStatsCardContent
              badge={badge}
              label={label}
              stats={stats}
              accentColor={accentColor}
              size={size}
            />
          )
        )}
      </ResourceStatsCardContainer>
    );
  },
);

ResourceStatsCard.displayName = "ResourceStatsCard";
