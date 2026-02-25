"use client";

import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { CheckIcon, MinusIcon } from "lucide-react";

import { cn } from "@/lib/utils";

const SIZE_STYLES = {
  default: {
    root: "size-6",
    icon: "size-4",
  },
  sm: {
    root: "size-5",
    icon: "size-3.5",
  },
} as const;

type CheckboxSize = keyof typeof SIZE_STYLES;

interface CheckboxProps
  extends React.ComponentProps<typeof CheckboxPrimitive.Root> {
  /** Size variant: "default" (24px) or "sm" (20px) */
  size?: CheckboxSize;
  /** Show indeterminate state (minus icon) - used for partial selection in trees */
  indeterminate?: boolean;
}

function Checkbox({
  className,
  size = "default",
  indeterminate,
  checked,
  ...props
}: CheckboxProps) {
  const sizeStyles = SIZE_STYLES[size];

  return (
    <CheckboxPrimitive.Root
      data-slot="checkbox"
      checked={indeterminate ? "indeterminate" : checked}
      className={cn(
        // Base styles
        "peer shrink-0 rounded-sm border transition-all outline-none",
        sizeStyles.root,
        // Default state
        "bg-bg-input-primary border-border-input-primary shadow-[0_1px_2px_0_rgba(0,0,0,0.1)]",
        // Checked state
        "data-[state=checked]:bg-button-tertiary-active data-[state=checked]:border-button-tertiary-active data-[state=checked]:text-white",
        // Indeterminate state
        "data-[state=indeterminate]:bg-button-tertiary-active data-[state=indeterminate]:border-button-tertiary-active data-[state=indeterminate]:text-white",
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
        {indeterminate ? (
          <MinusIcon className={sizeStyles.icon} />
        ) : (
          <CheckIcon className={sizeStyles.icon} />
        )}
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

export { Checkbox };
export type { CheckboxProps, CheckboxSize };
