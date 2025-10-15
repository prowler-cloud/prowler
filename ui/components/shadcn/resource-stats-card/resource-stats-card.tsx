import { cva, type VariantProps } from "class-variance-authority";
import { LucideIcon } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/utils";

export interface StatItem {
  icon: LucideIcon;
  label: string;
}

type CardSize = "sm" | "md" | "lg";

const variantColors = {
  fail: "#f54280",
  pass: "#4ade80",
  warning: "#fbbf24",
  info: "#60a5fa",
} as const;

type BadgeVariant = keyof typeof variantColors;

const sizeStyles: Record<
  CardSize,
  {
    headerIcon: string;
    headerTitle: string;
    resourceCount: string;
    emptyState: string;
    badgeIcon: string;
    labelText: string;
    statIcon: string;
    statLabel: string;
  }
> = {
  sm: {
    headerIcon: "h-3.5 w-3.5",
    headerTitle: "text-sm",
    resourceCount: "text-[9px]",
    emptyState: "text-xs",
    badgeIcon: "h-2.5 w-2.5",
    labelText: "text-xs",
    statIcon: "h-2.5 w-2.5",
    statLabel: "text-xs",
  },
  md: {
    headerIcon: "h-4 w-4",
    headerTitle: "text-base",
    resourceCount: "text-[10px]",
    emptyState: "text-sm",
    badgeIcon: "h-3 w-3",
    labelText: "text-sm",
    statIcon: "h-3 w-3",
    statLabel: "text-sm",
  },
  lg: {
    headerIcon: "h-5 w-5",
    headerTitle: "text-lg",
    resourceCount: "text-xs",
    emptyState: "text-base",
    badgeIcon: "h-4 w-4",
    labelText: "text-base",
    statIcon: "h-3.5 w-3.5",
    statLabel: "text-base",
  },
};

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
        fail: ["bg-[#432232]", `text-[${variantColors.fail}]`],
        pass: ["bg-[#204237]", `text-[${variantColors.pass}]`],
        warning: ["bg-[#3d3520]", `text-[${variantColors.warning}]`],
        info: ["bg-[#1e3a5f]", `text-[${variantColors.info}]`],
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
    variant?: "fail" | "pass" | "warning" | "info";
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
    const resolvedSize: CardSize = size ?? "md";
    const BadgeIconComponent = badge?.icon;
    const HeaderIcon = header?.icon;
    const badgeVariantUnresolved = badge?.variant ?? variant ?? "fail";
    const badgeVariant: BadgeVariant =
      badgeVariantUnresolved === "default"
        ? "fail"
        : (badgeVariantUnresolved as BadgeVariant);
    const currentSizeStyles = sizeStyles[resolvedSize];
    const showBadgeRow = Boolean(badge && label && BadgeIconComponent);
    const showStats = stats.length > 0;

    // Determine accent line color
    const lineColor = accentColor || variantColors[badgeVariant] || "#d4d4d8";

    return (
      <div
        ref={ref}
        className={cn(
          resourceStatsCardVariants({ variant, size: resolvedSize }),
          className,
        )}
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
                    currentSizeStyles.headerIcon,
                  )}
                  strokeWidth={2}
                />
              )}
              <span
                className={cn(
                  "leading-7 font-semibold text-zinc-300 dark:text-zinc-300",
                  currentSizeStyles.headerTitle,
                )}
              >
                {header.title}
              </span>
            </div>
            {header.resourceCount !== undefined && (
              <span
                className={cn(
                  "leading-4 font-normal text-zinc-400 dark:text-zinc-400",
                  currentSizeStyles.resourceCount,
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
                currentSizeStyles.emptyState,
              )}
            >
              {emptyState.message}
            </p>
          </div>
        ) : (
          <>
            {/* Badge and Label Row */}
            {showBadgeRow && BadgeIconComponent && badge && (
              <div className="flex w-full items-center gap-1">
                {/* Badge */}
                <div
                  className={cn(
                    badgeVariants({
                      variant: badgeVariant,
                      size: resolvedSize,
                    }),
                  )}
                >
                  <BadgeIconComponent
                    className={currentSizeStyles.badgeIcon}
                    strokeWidth={2.5}
                  />
                  <span className="leading-6 font-bold">{badge.count}</span>
                </div>

                {/* Label */}
                <span
                  className={cn(
                    "leading-6 font-semibold text-zinc-300 dark:text-zinc-300",
                    currentSizeStyles.labelText,
                  )}
                >
                  {label}
                </span>
              </div>
            )}

            {/* Stats Section */}
            {showStats && (
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
                            currentSizeStyles.statIcon,
                          )}
                          strokeWidth={2}
                        />
                        <span
                          className={cn(
                            "leading-5 font-medium text-zinc-300 dark:text-zinc-300",
                            currentSizeStyles.statLabel,
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
