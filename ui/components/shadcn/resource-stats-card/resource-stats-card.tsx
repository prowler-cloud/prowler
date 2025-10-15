import { cva, type VariantProps } from "class-variance-authority";
import { LucideIcon } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/utils";

export interface StatItem {
  icon: LucideIcon;
  label: string;
  count?: number | string;
}

const resourceStatsCardVariants = cva(
  [
    "flex",
    "flex-col",
    "gap-2",
    "rounded-xl",
    "border",
    "px-3",
    "py-2",
    "backdrop-blur-[46px]",
  ],
  {
    variants: {
      variant: {
        default: [
          "border-[rgba(38,38,38,0.7)]",
          "bg-[rgba(23,23,23,0.5)]",
          "dark:border-[rgba(38,38,38,0.7)]",
          "dark:bg-[rgba(23,23,23,0.5)]",
        ],
        fail: [
          "border-[rgba(67,34,50,0.5)]",
          "bg-[rgba(67,34,50,0.2)]",
          "dark:border-[rgba(67,34,50,0.7)]",
          "dark:bg-[rgba(67,34,50,0.3)]",
        ],
        pass: [
          "border-[rgba(32,66,55,0.5)]",
          "bg-[rgba(32,66,55,0.2)]",
          "dark:border-[rgba(32,66,55,0.7)]",
          "dark:bg-[rgba(32,66,55,0.3)]",
        ],
        warning: [
          "border-[rgba(61,53,32,0.5)]",
          "bg-[rgba(61,53,32,0.2)]",
          "dark:border-[rgba(61,53,32,0.7)]",
          "dark:bg-[rgba(61,53,32,0.3)]",
        ],
        info: [
          "border-[rgba(30,58,95,0.5)]",
          "bg-[rgba(30,58,95,0.2)]",
          "dark:border-[rgba(30,58,95,0.7)]",
          "dark:bg-[rgba(30,58,95,0.3)]",
        ],
      },
      size: {
        sm: ["px-2", "py-1.5", "gap-1"],
        md: ["px-3", "py-2", "gap-2"],
        lg: ["px-4", "py-3", "gap-3"],
      },
    },
    defaultVariants: {
      variant: "default",
      size: "md",
    },
  },
);

const badgeVariants = cva(
  ["flex", "items-center", "justify-center", "gap-0.5", "rounded-full"],
  {
    variants: {
      variant: {
        fail: ["bg-[#432232]", "text-[#f54280]"],
        pass: ["bg-[#204237]", "text-[#4ade80]"],
        warning: ["bg-[#3d3520]", "text-[#fbbf24]"],
        info: ["bg-[#1e3a5f]", "text-[#60a5fa]"],
        custom: [], // For custom colors
      },
      size: {
        sm: ["px-1", "text-xs"],
        md: ["px-1.5", "text-sm"],
        lg: ["px-2", "text-base"],
      },
    },
    defaultVariants: {
      variant: "fail",
      size: "md",
    },
  },
);

export interface ResourceStatsCardProps
  extends Omit<React.HTMLAttributes<HTMLDivElement>, "color">,
    VariantProps<typeof resourceStatsCardVariants> {
  // Optional header (icon + title + resource count)
  header?: {
    icon: LucideIcon;
    title: string;
    resourceCount?: number | string; // e.g., "52 Resources" or 52
  };

  // Empty state message (when there's no data to display)
  emptyState?: {
    message: string; // e.g., "No Findings to display"
  };

  // Main badge (top section) - optional when using empty state
  badge?: {
    icon: LucideIcon;
    count: number | string;
    variant?: "fail" | "pass" | "warning" | "info" | "custom";
    backgroundColor?: string; // For custom variant
    textColor?: string; // For custom variant
  };

  // Main label - optional when using empty state
  label?: string;

  // Vertical accent line color (optional, auto-determined from variant)
  accentColor?: string;

  // Sub-statistics array (flexible items)
  stats?: StatItem[];
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
      variant,
      size = "md",
      className,
      ...props
    },
    ref,
  ) => {
    const BadgeIcon = badge?.icon;
    const HeaderIcon = header?.icon;
    // Use badge variant, fallback to card variant, or default to "fail"
    // Map "default" variant to "fail" for badge colors
    const determineVariant = () => {
      const v = badge?.variant || variant || "fail";
      return v === "default" ? "fail" : v;
    };
    const badgeVariant = determineVariant();

    // Determine accent color based on variant
    const getAccentColor = () => {
      if (accentColor) return accentColor;
      if (badge?.textColor) return badge.textColor;

      // Default colors based on badge variant
      const variantColors: Record<string, string> = {
        fail: "#f54280",
        pass: "#4ade80",
        warning: "#fbbf24",
        info: "#60a5fa",
        custom: badge?.textColor || "#d4d4d8",
      };

      return variantColors[badgeVariant] || "#d4d4d8";
    };

    const lineColor = getAccentColor();

    // Custom inline styles for custom variant
    const badgeStyle =
      badgeVariant === "custom" && badge
        ? {
            backgroundColor: badge.backgroundColor,
            color: badge.textColor,
          }
        : undefined;

    return (
      <div
        ref={ref}
        className={cn(resourceStatsCardVariants({ variant, size }), className)}
        {...props}
      >
        {/* Optional Header */}
        {header && (
          <div className="flex w-full items-center gap-1">
            <div className="flex flex-1 items-center gap-1">
              {HeaderIcon && (
                <HeaderIcon
                  className={cn(
                    "text-zinc-300 dark:text-zinc-300",
                    size === "sm" && "h-3.5 w-3.5",
                    size === "md" && "h-4 w-4",
                    size === "lg" && "h-5 w-5",
                  )}
                  strokeWidth={2}
                />
              )}
              <span
                className={cn(
                  "leading-7 font-semibold text-zinc-300 dark:text-zinc-300",
                  size === "sm" && "text-sm",
                  size === "md" && "text-base",
                  size === "lg" && "text-lg",
                )}
              >
                {header.title}
              </span>
            </div>
            {header.resourceCount !== undefined && (
              <span
                className={cn(
                  "leading-4 font-normal text-zinc-400 dark:text-zinc-400",
                  size === "sm" && "text-[9px]",
                  size === "md" && "text-[10px]",
                  size === "lg" && "text-xs",
                )}
              >
                {typeof header.resourceCount === "number"
                  ? `${header.resourceCount} Resources`
                  : header.resourceCount}
              </span>
            )}
          </div>
        )}

        {/* Empty State */}
        {emptyState ? (
          <div className="flex h-[51px] w-full flex-col items-center justify-center">
            <p
              className={cn(
                "text-center leading-5 font-medium text-zinc-600 dark:text-zinc-600",
                size === "sm" && "text-xs",
                size === "md" && "text-sm",
                size === "lg" && "text-base",
              )}
            >
              {emptyState.message}
            </p>
          </div>
        ) : (
          <>
            {/* Badge and Label Row */}
            {badge && label && BadgeIcon && (
              <div className="flex w-full items-center gap-1">
                {/* Badge */}
                <div
                  className={cn(badgeVariants({ variant: badgeVariant, size }))}
                  style={badgeStyle}
                >
                  <BadgeIcon
                    className={cn(
                      "h-3 w-3",
                      size === "sm" && "h-2.5 w-2.5",
                      size === "lg" && "h-4 w-4",
                    )}
                    strokeWidth={2.5}
                  />
                  <span className="leading-6 font-bold">{badge.count}</span>
                </div>

                {/* Label */}
                <span
                  className={cn(
                    "leading-6 font-semibold text-zinc-300 dark:text-zinc-300",
                    size === "sm" && "text-xs",
                    size === "md" && "text-sm",
                    size === "lg" && "text-base",
                  )}
                >
                  {label}
                </span>
              </div>
            )}

            {/* Stats Section */}
            {stats.length > 0 && (
              <div className="flex w-full items-stretch gap-0">
                {/* Vertical Accent Line */}
                <div className="flex items-stretch px-3 py-1">
                  <div
                    className="w-px rounded-full"
                    style={{ backgroundColor: lineColor }}
                  />
                </div>

                {/* Stats List */}
                <div className="flex flex-1 flex-col gap-0.5">
                  {stats.map((stat, index) => {
                    const StatIcon = stat.icon;
                    return (
                      <div key={index} className="flex items-center gap-1">
                        <StatIcon
                          className={cn(
                            "text-zinc-300 dark:text-zinc-300",
                            size === "sm" && "h-2.5 w-2.5",
                            size === "md" && "h-3 w-3",
                            size === "lg" && "h-3.5 w-3.5",
                          )}
                          strokeWidth={2}
                        />
                        <span
                          className={cn(
                            "leading-5 font-medium text-zinc-300 dark:text-zinc-300",
                            size === "sm" && "text-xs",
                            size === "md" && "text-sm",
                            size === "lg" && "text-base",
                          )}
                        >
                          {stat.label}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    );
  },
);

ResourceStatsCard.displayName = "ResourceStatsCard";
