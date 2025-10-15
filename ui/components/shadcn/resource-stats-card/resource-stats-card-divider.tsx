import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const dividerVariants = cva("flex items-center justify-center", {
  variants: {
    spacing: {
      sm: "px-2",
      md: "px-[23px]",
      lg: "px-8",
    },
    orientation: {
      vertical: "h-full",
      horizontal: "w-full",
    },
  },
  defaultVariants: {
    spacing: "md",
    orientation: "vertical",
  },
});

const lineVariants = cva("bg-[rgba(39,39,42,1)]", {
  variants: {
    orientation: {
      vertical: "h-full w-px",
      horizontal: "w-full h-px",
    },
  },
  defaultVariants: {
    orientation: "vertical",
  },
});

export interface ResourceStatsCardDividerProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof dividerVariants> {}

export const ResourceStatsCardDivider = React.forwardRef<
  HTMLDivElement,
  ResourceStatsCardDividerProps
>(({ className, spacing, orientation, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn(dividerVariants({ spacing, orientation }), className)}
      {...props}
    >
      <div className={lineVariants({ orientation })} />
    </div>
  );
});

ResourceStatsCardDivider.displayName = "ResourceStatsCardDivider";
