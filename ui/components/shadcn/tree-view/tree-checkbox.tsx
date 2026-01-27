"use client";

import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { CheckIcon, MinusIcon } from "lucide-react";

import { cn } from "@/lib/utils";
import { TreeCheckboxProps } from "@/types/tree";

/**
 * TreeCheckbox component with indeterminate state support.
 *
 * Uses Radix UI's "indeterminate" checked state to show a minus icon
 * when a parent node has some (but not all) children selected.
 */
export function TreeCheckbox({
  checked,
  indeterminate,
  onCheckedChange,
  disabled,
}: TreeCheckboxProps) {
  return (
    <CheckboxPrimitive.Root
      checked={indeterminate ? "indeterminate" : checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      data-slot="tree-checkbox"
      className={cn(
        // Base styles - 20x20px (slightly smaller than form checkbox)
        "peer size-5 shrink-0 rounded-sm border transition-all outline-none",
        // Default state
        "bg-bg-input-primary border-border-input-primary",
        // Checked state
        "data-[state=checked]:bg-button-primary data-[state=checked]:border-button-primary data-[state=checked]:text-white",
        // Indeterminate state
        "data-[state=indeterminate]:bg-button-primary data-[state=indeterminate]:border-button-primary data-[state=indeterminate]:text-white",
        // Focus state
        "focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press/50 focus-visible:ring-2",
        // Disabled state
        "disabled:cursor-not-allowed disabled:opacity-40",
      )}
      onClick={(e) => e.stopPropagation()}
    >
      <CheckboxPrimitive.Indicator
        data-slot="tree-checkbox-indicator"
        className="grid place-content-center text-current"
      >
        {indeterminate ? (
          <MinusIcon className="size-3.5" />
        ) : (
          <CheckIcon className="size-3.5" />
        )}
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}
