"use client";

import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { CheckIcon } from "lucide-react";

import { cn } from "@/lib/utils";

function Checkbox({
  className,
  ...props
}: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      data-slot="checkbox"
      className={cn(
        // Base styles - 24x24px
        "peer size-6 shrink-0 rounded-sm border transition-all outline-none",
        // Default state
        "bg-bg-input-primary border-border-input-primary shadow-[0_1px_2px_0_rgba(0,0,0,0.1)]",
        // Checked state
        "data-[state=checked]:bg-button-primary data-[state=checked]:border-button-primary data-[state=checked]:text-white",
        // Focus state
        "focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press/50 focus-visible:ring-2",
        // Disabled state
        "disabled:bg-bg-input-primary/50 disabled:border-border-input-primary/50 disabled:cursor-not-allowed disabled:opacity-40 disabled:shadow-none",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator
        data-slot="checkbox-indicator"
        className="grid place-content-center text-current transition-none"
      >
        <CheckIcon className="size-4" />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

export { Checkbox };
