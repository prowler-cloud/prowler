"use client";

import * as ProgressPrimitive from "@radix-ui/react-progress";
import { ComponentProps } from "react";

import { cn } from "@/lib/utils";

interface ProgressProps extends ComponentProps<typeof ProgressPrimitive.Root> {
  indicatorClassName?: string;
}

function Progress({
  className,
  value = 0,
  indicatorClassName,
  ...props
}: ProgressProps) {
  const normalizedValue = value ?? 0;

  return (
    <ProgressPrimitive.Root
      data-slot="progress"
      value={normalizedValue}
      className={cn(
        "border-border-neutral-secondary bg-bg-neutral-secondary relative h-2 w-full overflow-hidden rounded-full border transition-colors duration-200 ease-out motion-reduce:transition-none",
        className,
      )}
      {...props}
    >
      <ProgressPrimitive.Indicator
        data-slot="progress-indicator"
        className={cn(
          "bg-button-primary h-full w-full flex-1 transition-transform duration-300 ease-out motion-reduce:transition-none",
          indicatorClassName,
        )}
        style={{ transform: `translateX(-${100 - normalizedValue}%)` }}
      />
    </ProgressPrimitive.Root>
  );
}

export { Progress };
