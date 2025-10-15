import { cva } from "class-variance-authority";
import { LucideIcon } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/utils";

export interface StatItem {
  icon: LucideIcon;
  label: string;
}

const variantColors = {
  fail: "#f54280",
  pass: "#4ade80",
  warning: "#fbbf24",
  info: "#60a5fa",
} as const;

type BadgeVariant = keyof typeof variantColors;

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

const sizeStyles = {
  sm: {
    badgeIcon: "h-2.5 w-2.5",
    labelText: "text-xs",
    statIcon: "h-2.5 w-2.5",
    statLabel: "text-xs",
  },
  md: {
    badgeIcon: "h-3 w-3",
    labelText: "text-sm",
    statIcon: "h-3 w-3",
    statLabel: "text-sm",
  },
  lg: {
    badgeIcon: "h-4 w-4",
    labelText: "text-base",
    statIcon: "h-3.5 w-3.5",
    statLabel: "text-base",
  },
};

export interface ResourceStatsCardContentProps
  extends React.HTMLAttributes<HTMLDivElement> {
  badge: {
    icon: LucideIcon;
    count: number | string;
    variant?: "fail" | "pass" | "warning" | "info";
  };
  label: string;
  stats?: StatItem[];
  accentColor?: string;
  size?: "sm" | "md" | "lg";
}

export const ResourceStatsCardContent = React.forwardRef<
  HTMLDivElement,
  ResourceStatsCardContentProps
>(
  (
    { badge, label, stats = [], accentColor, size = "md", className, ...props },
    ref,
  ) => {
    const BadgeIcon = badge.icon;
    const badgeVariant: BadgeVariant = badge.variant || "fail";
    const styles = sizeStyles[size];

    // Determine accent line color
    const lineColor = accentColor || variantColors[badgeVariant] || "#d4d4d8";

    return (
      <div
        ref={ref}
        className={cn("flex flex-col gap-[5px]", className)}
        {...props}
      >
        {/* Badge and Label Row */}
        <div className="flex w-full items-center gap-1">
          {/* Badge */}
          <div className={cn(badgeVariants({ variant: badgeVariant, size }))}>
            <BadgeIcon className={styles.badgeIcon} strokeWidth={2.5} />
            <span className="leading-6 font-bold">{badge.count}</span>
          </div>

          {/* Label */}
          <span
            className={cn(
              "leading-6 font-semibold text-zinc-300 dark:text-zinc-300",
              styles.labelText,
            )}
          >
            {label}
          </span>
        </div>

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
                        styles.statIcon,
                      )}
                      strokeWidth={2}
                    />
                    <span
                      className={cn(
                        "leading-5 font-medium text-zinc-300 dark:text-zinc-300",
                        styles.statLabel,
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
      </div>
    );
  },
);

ResourceStatsCardContent.displayName = "ResourceStatsCardContent";
