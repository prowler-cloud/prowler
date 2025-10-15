import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const containerVariants = cva(
  [
    "flex",
    "rounded-[12px]",
    "border",
    "backdrop-blur-[46px]",
    "border-[rgba(38,38,38,0.70)]",
    "bg-[rgba(23,23,23,0.50)]",
    "dark:border-[rgba(38,38,38,0.70)]",
    "dark:bg-[rgba(23,23,23,0.50)]",
  ],
  {
    variants: {
      padding: {
        default: "px-[19px] py-[9px]",
        sm: "px-3 py-2",
        md: "px-[19px] py-[9px]",
        lg: "px-6 py-3",
        none: "p-0",
      },
    },
    defaultVariants: {
      padding: "default",
    },
  },
);

export interface ResourceStatsCardContainerProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof containerVariants> {}

export const ResourceStatsCardContainer = React.forwardRef<
  HTMLDivElement,
  ResourceStatsCardContainerProps
>(({ className, children, padding, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn(containerVariants({ padding }), className)}
      {...props}
    >
      {children}
    </div>
  );
});

ResourceStatsCardContainer.displayName = "ResourceStatsCardContainer";
