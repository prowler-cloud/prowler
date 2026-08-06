"use client";

import * as ProgressPrimitive from "@radix-ui/react-progress";
import { ComponentProps } from "react";

import { cn } from "@/lib/utils";

interface ProgressProps extends ComponentProps<typeof ProgressPrimitive.Root> {
  indicatorClassName?: string;
  variant?: ProgressVariant;
  size?: ProgressSize;
}

const PROGRESS_VARIANT = {
  DEFAULT: "default",
  SUCCESS: "success",
  WARNING: "warning",
  DANGER: "danger",
  LIGHTHOUSE: "lighthouse",
} as const;

type ProgressVariant = (typeof PROGRESS_VARIANT)[keyof typeof PROGRESS_VARIANT];

const PROGRESS_SIZE = {
  DEFAULT: "default",
  COMPACT: "compact",
} as const;

type ProgressSize = (typeof PROGRESS_SIZE)[keyof typeof PROGRESS_SIZE];

const indicatorVariants = {
  default: "bg-button-primary",
  success: "bg-bg-pass",
  warning: "bg-bg-warning",
  danger: "bg-bg-fail",
  lighthouse: "bg-lighthouse animate-pulse duration-500",
} as const;

const rootSizeVariants = {
  default: "border-border-neutral-secondary bg-bg-neutral-secondary h-2 border",
  compact: "bg-bg-neutral-tertiary h-1",
} as const;

function Progress({
  className,
  value = 0,
  indicatorClassName,
  variant = PROGRESS_VARIANT.DEFAULT,
  size = PROGRESS_SIZE.DEFAULT,
  ...props
}: ProgressProps) {
  const normalizedValue = value ?? 0;

  return (
    <ProgressPrimitive.Root
      data-slot="progress"
      value={normalizedValue}
      className={cn(
        "relative w-full overflow-hidden rounded-full",
        rootSizeVariants[size],
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
