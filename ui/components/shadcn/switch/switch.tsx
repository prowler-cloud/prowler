"use client";

import * as SwitchPrimitive from "@radix-ui/react-switch";
import { ComponentProps } from "react";

import { cn } from "@/lib/utils";

function Switch({
  className,
  ...props
}: ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      className={cn(
        // Base styles
        "peer inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border transition-all outline-none",
        // Default state
        "bg-bg-input-primary border-border-input-primary shadow-[0_1px_2px_0_rgba(0,0,0,0.1)]",
        // Checked state
        "data-[state=checked]:bg-button-primary data-[state=checked]:border-button-primary",
        // Focus state
        "focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press/50 focus-visible:ring-2",
        // Disabled state
        "disabled:cursor-not-allowed disabled:opacity-40 disabled:shadow-none",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className={cn(
          "bg-border-input-primary-fill pointer-events-none block size-5 rounded-full shadow-[0_1px_2px_0_rgba(0,0,0,0.2)] transition-transform",
          "data-[state=checked]:translate-x-[21px] data-[state=checked]:bg-white data-[state=unchecked]:translate-x-px",
        )}
      />
    </SwitchPrimitive.Root>
  );
}

export { Switch };
