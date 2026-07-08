import { cva, type VariantProps } from "class-variance-authority";
import { LucideIcon } from "lucide-react";

import { Card, CardVariant } from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";

import type { StatItem } from "./resource-stats-card-content";
import { ResourceStatsCardContent } from "./resource-stats-card-content";
import { ResourceStatsCardHeader } from "./resource-stats-card-header";

export type { StatItem };
const cardVariants = cva("", {
  variants: {
    variant: {
      [CardVariant.default]: "",
      // Fail variant - rgba(67,34,50) from Figma
      [CardVariant.fail]:
        "border-[rgba(67,34,50,0.5)] bg-[rgba(67,34,50,0.2)] dark:border-[rgba(67,34,50,0.7)] dark:bg-[rgba(67,34,50,0.3)]",
      // Pass variant - rgba(32,66,55) from Figma
      [CardVariant.pass]:
        "border-[rgba(32,66,55,0.5)] bg-[rgba(32,66,55,0.2)] dark:border-[rgba(32,66,55,0.7)] dark:bg-[rgba(32,66,55,0.3)]",
      // Warning variant - rgba(61,53,32) from Figma
      [CardVariant.warning]:
        "border-[rgba(61,53,32,0.5)] bg-[rgba(61,53,32,0.2)] dark:border-[rgba(61,53,32,0.7)] dark:bg-[rgba(61,53,32,0.3)]",
      // Info variant - rgba(30,58,95) from Figma
      [CardVariant.info]:
        "border-[rgba(30,58,95,0.5)] bg-[rgba(30,58,95,0.2)] dark:border-[rgba(30,58,95,0.7)] dark:bg-[rgba(30,58,95,0.3)]",
    },
    size: {
      sm: "px-2 py-1.5 gap-1",
      md: "px-3 py-2 gap-2",
      lg: "px-4 py-3 gap-3",
    },
  },
  defaultVariants: {
    variant: CardVariant.default,
    size: "md",
  },
});

// Neutral surface + colored top bar; reads well in both light and dark modes.
const accentBarByVariant: Record<CardVariant, string> = {
  [CardVariant.default]: "",
  [CardVariant.fail]: "bg-bg-fail-primary",
  [CardVariant.pass]: "bg-bg-pass-primary",
  [CardVariant.warning]: "bg-bg-warning-primary",
  [CardVariant.info]: "bg-bg-data-info",
};

export interface ResourceStatsCardProps
  extends Omit<React.HTMLAttributes<HTMLDivElement>, "color">,
    VariantProps<typeof cardVariants> {
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
    variant?: CardVariant;
  };

  // Main label - optional when using empty state
  label?: string;

  // Vertical accent line color (optional, auto-determined from variant)
  accentColor?: string;

  // Horizontal top accent bar. When set, the card renders on a neutral surface
  // with a colored bar across the top using design tokens. Prefer this over
  // `variant` when the surface needs to read well in both light and dark modes.
  accent?: CardVariant;

  // Sub-statistics array (flexible items)
  stats?: StatItem[];

  // Render without container (no border, background, padding) - useful for composing multiple cards in a custom container
  containerless?: boolean;

  // Ref for the root element
  ref?: React.Ref<HTMLDivElement>;
}

export const ResourceStatsCard = ({
  header,
  emptyState,
  badge,
  label,
  accentColor,
  accent,
  stats = [],
  variant = CardVariant.default,
  size = "md",
  containerless = false,
  className,
  ref,
  ...props
}: ResourceStatsCardProps) => {
  // Resolve size to ensure it's not null (CVA can return null but we need a defined value)
  const resolvedSize = size || "md";

  // `accent` takes precedence: it forces a neutral surface and a colored top bar,
  // so the card reads well in both themes regardless of `variant`.
  const resolvedVariant = accent ? CardVariant.default : variant;
  const accentClassName = accent ? accentBarByVariant[accent] : "";

  // If containerless, render without outer wrapper. `accent` is ignored in this
  // mode because the caller supplies the container; consumers that need the
  // accent bar can render it themselves or drop containerless.
  if (containerless) {
    return (
      <div
        ref={ref}
        className={cn("flex flex-col gap-[5px]", className)}
        {...props}
      >
        {header && <ResourceStatsCardHeader {...header} size={resolvedSize} />}
        {emptyState ? (
          <div className="flex h-[51px] w-full flex-col items-start justify-center md:items-center">
            <p className="text-text-neutral-secondary text-center text-sm leading-5 font-medium">
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
              size={resolvedSize}
            />
          )
        )}
      </div>
    );
  }

  // Otherwise, render with container
  return (
    <Card
      ref={ref}
      variant="inner"
      className={cn(
        cardVariants({ variant: resolvedVariant, size }),
        "flex-col",
        accent &&
          "border-border-neutral-secondary bg-bg-neutral-secondary relative overflow-hidden",
        className,
      )}
      {...props}
    >
      {accent && (
        <span
          aria-hidden
          data-slot="resource-stats-card-accent"
          className={cn(
            "absolute inset-x-0 top-0 h-1 rounded-t-[inherit]",
            accentClassName,
          )}
        />
      )}
      {header && <ResourceStatsCardHeader {...header} size={resolvedSize} />}
      {emptyState ? (
        <div className="flex h-[51px] w-full flex-col items-center justify-center">
          <p className="text-text-neutral-secondary text-center text-sm leading-5 font-medium">
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
            size={resolvedSize}
          />
        )
      )}
    </Card>
  );
};

ResourceStatsCard.displayName = "ResourceStatsCard";
