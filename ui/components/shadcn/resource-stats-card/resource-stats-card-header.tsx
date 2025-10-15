import { cva, type VariantProps } from "class-variance-authority";
import { LucideIcon } from "lucide-react";
import * as React from "react";

import { cn } from "@/lib/utils";

const headerVariants = cva("flex w-full items-center gap-1", {
  variants: {
    size: {
      sm: "",
      md: "",
      lg: "",
    },
  },
  defaultVariants: {
    size: "md",
  },
});

const iconVariants = cva("text-zinc-300 dark:text-zinc-300", {
  variants: {
    size: {
      sm: "h-3.5 w-3.5",
      md: "h-4 w-4",
      lg: "h-5 w-5",
    },
  },
  defaultVariants: {
    size: "md",
  },
});

const titleVariants = cva(
  "leading-7 font-semibold text-zinc-300 dark:text-zinc-300",
  {
    variants: {
      size: {
        sm: "text-sm",
        md: "text-base",
        lg: "text-lg",
      },
    },
    defaultVariants: {
      size: "md",
    },
  },
);

const countVariants = cva(
  "leading-4 font-normal text-zinc-300 dark:text-zinc-300",
  {
    variants: {
      size: {
        sm: "text-[9px]",
        md: "text-[10px]",
        lg: "text-xs",
      },
    },
    defaultVariants: {
      size: "md",
    },
  },
);

export interface ResourceStatsCardHeaderProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof headerVariants> {
  icon: LucideIcon;
  title: string;
  resourceCount?: number | string;
}

export const ResourceStatsCardHeader = React.forwardRef<
  HTMLDivElement,
  ResourceStatsCardHeaderProps
>(
  (
    { icon: Icon, title, resourceCount, size = "md", className, ...props },
    ref,
  ) => {
    return (
      <div
        ref={ref}
        className={cn(headerVariants({ size }), className)}
        {...props}
      >
        <div className="flex flex-1 items-center gap-1">
          <Icon className={iconVariants({ size })} strokeWidth={2} />
          <span className={titleVariants({ size })}>{title}</span>
        </div>
        {resourceCount !== undefined && (
          <span className={countVariants({ size })}>
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
