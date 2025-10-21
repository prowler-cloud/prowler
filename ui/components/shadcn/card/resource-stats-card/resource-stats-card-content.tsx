import { cva } from "class-variance-authority";
import { LucideIcon } from "lucide-react";

import { cn } from "@/lib/utils";

export interface StatItem {
  icon: LucideIcon;
  label: string;
}

export const CardVariant = {
  default: "default",
  fail: "fail",
  pass: "pass",
  warning: "warning",
  info: "info",
} as const;

export type CardVariant = (typeof CardVariant)[keyof typeof CardVariant];

const variantColors = {
  default: "#868994",
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
        [CardVariant.default]: "bg-[#535359]",
        [CardVariant.fail]: "bg-[#432232]",
        [CardVariant.pass]: "bg-[#204237]",
        [CardVariant.warning]: "bg-[#3d3520]",
        [CardVariant.info]: "bg-[#1e3a5f]",
      },
      size: {
        sm: "px-1 text-xs",
        md: "px-1.5 text-sm",
        lg: "px-2 text-base",
      },
    },
    defaultVariants: {
      variant: CardVariant.fail,
      size: "md",
    },
  },
);

const badgeIconVariants = cva("", {
  variants: {
    size: {
      sm: "h-2.5 w-2.5",
      md: "h-3 w-3",
      lg: "h-4 w-4",
    },
  },
  defaultVariants: {
    size: "md",
  },
});

const labelTextVariants = cva(
  "leading-6 font-semibold text-zinc-300 dark:text-zinc-300 whitespace-nowrap",
  {
    variants: {
      size: {
        sm: "text-xs",
        md: "text-sm",
        lg: "text-base",
      },
    },
    defaultVariants: {
      size: "md",
    },
  },
);

const statIconVariants = cva("text-zinc-300 dark:text-zinc-300", {
  variants: {
    size: {
      sm: "h-2.5 w-2.5",
      md: "h-3 w-3",
      lg: "h-3.5 w-3.5",
    },
  },
  defaultVariants: {
    size: "md",
  },
});

const statLabelVariants = cva(
  "leading-5 font-medium text-zinc-300 dark:text-zinc-300",
  {
    variants: {
      size: {
        sm: "text-xs",
        md: "text-sm",
        lg: "text-base",
      },
    },
    defaultVariants: {
      size: "md",
    },
  },
);

export interface ResourceStatsCardContentProps
  extends React.HTMLAttributes<HTMLDivElement> {
  badge: {
    icon: LucideIcon;
    count: number | string;
    variant?: CardVariant;
  };
  label: string;
  stats?: StatItem[];
  accentColor?: string;
  size?: "sm" | "md" | "lg";
  ref?: React.Ref<HTMLDivElement>;
}

export const ResourceStatsCardContent = ({
  badge,
  label,
  stats = [],
  accentColor,
  size = "md",
  className,
  ref,
  ...props
}: ResourceStatsCardContentProps) => {
  const BadgeIcon = badge.icon;
  const badgeVariant: BadgeVariant = badge.variant || "fail";

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
          <BadgeIcon
            className={badgeIconVariants({ size })}
            strokeWidth={2.5}
            style={{ color: variantColors[badgeVariant] }}
          />
          <span
            className="leading-6 font-bold"
            style={{ color: variantColors[badgeVariant] }}
          >
            {badge.count}
          </span>
        </div>

        {/* Label */}
        <span className={labelTextVariants({ size })}>{label}</span>
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
                    className={statIconVariants({ size })}
                    strokeWidth={2}
                  />
                  <span className={statLabelVariants({ size })}>
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
};

ResourceStatsCardContent.displayName = "ResourceStatsCardContent";
