"use client";

import * as ProgressPrimitive from "@radix-ui/react-progress";
import { ComponentProps } from "react";

import { cn } from "@/lib/utils";

interface ProgressProps extends ComponentProps<typeof ProgressPrimitive.Root> {
  indicatorClassName?: string;
  variant?: "default" | "success" | "warning" | "danger";
}

const indicatorVariants = {
  default: "bg-button-primary",
  success: "bg-bg-pass",
  warning: "bg-bg-warning",
  danger: "bg-bg-fail",
} as const;

function Progress({
  className,
  value = 0,
  indicatorClassName,
  variant = "default",
  ...props
}: ProgressProps) {
  const normalizedValue = value ?? 0;

  return (
    <ProgressPrimitive.Root
      data-slot="progress"
      value={normalizedValue}
      className={cn(
        "border-border-neutral-secondary bg-bg-neutral-secondary relative h-2 w-full overflow-hidden rounded-full border",
        className,
      )}
      {...props}
    >
      <ProgressPrimitive.Indicator
        data-slot="progress-indicator"
        className={cn(
          "h-full w-full flex-1 transition-all",
          indicatorVariants[variant],
          indicatorClassName,
        )}
        style={{ transform: `translateX(-${100 - normalizedValue}%)` }}
      />
    </ProgressPrimitive.Root>
  );
}

export { Progress };
