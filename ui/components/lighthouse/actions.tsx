"use client";

import { Button } from "@heroui/button";
import type { PressEvent } from "@react-types/shared";
import * as React from "react";

import { cn } from "@/lib/utils";

// ============================================================================
// Actions Component - Container for action buttons
// ============================================================================

interface ActionsProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string;
  children?: React.ReactNode;
}

const Actions = React.forwardRef<HTMLDivElement, ActionsProps>(
  ({ className, children, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "border-default-200 bg-default-50 dark:border-default-100 dark:bg-default-100/50 flex flex-wrap items-center gap-2 rounded-lg border p-2",
          className,
        )}
        {...props}
      >
        {children}
      </div>
    );
  },
);
Actions.displayName = "Actions";

// ============================================================================
// Action Component - Individual action button
// ============================================================================

interface ActionProps {
  /**
   * Action label text
   */
  label: string;
  /**
   * Optional icon component (Lucide React icon recommended)
   */
  icon?: React.ReactNode;
  /**
   * Click handler
   */
  onClick?: (e: PressEvent) => void;
  /**
   * Visual variant
   * @default "light"
   */
  variant?: "solid" | "bordered" | "light" | "flat" | "faded" | "shadow";
  className?: string;
  isDisabled?: boolean;
}

const Action = React.forwardRef<HTMLButtonElement, ActionProps>(
  (
    {
      label,
      icon,
      onClick,
      variant = "light",
      className,
      isDisabled = false,
      ...props
    },
    ref,
  ) => {
    return (
      <Button
        ref={ref}
        variant={variant}
        size="sm"
        onPress={onClick}
        isDisabled={isDisabled}
        className={cn(
          "min-w-unit-16 gap-1.5 text-xs font-medium transition-all hover:scale-105",
          className,
        )}
        startContent={icon}
        {...props}
      >
        {label}
      </Button>
    );
  },
);
Action.displayName = "Action";

export { Action, Actions };
