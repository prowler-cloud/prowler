"use client";

import { MoreHorizontal } from "lucide-react";
import { ComponentProps, ReactNode } from "react";

import { cn } from "@/lib/utils";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./dropdown";

interface ActionDropdownProps {
  /** The dropdown trigger element. Defaults to a vertical dots icon button */
  trigger?: ReactNode;
  /** Label shown at the top of the dropdown */
  label?: string;
  /** Alignment of the dropdown content */
  align?: "start" | "center" | "end";
  /** Additional className for the content */
  className?: string;
  /** Accessible label for the trigger */
  ariaLabel?: string;
  children: ReactNode;
}

export function ActionDropdown({
  trigger,
  label = "Actions",
  align = "end",
  className,
  ariaLabel = "Open actions menu",
  children,
}: ActionDropdownProps) {
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        {trigger ?? (
          <button
            type="button"
            aria-label={ariaLabel}
            className="hover:bg-bg-neutral-tertiary rounded-md p-1 transition-colors"
          >
            <MoreHorizontal className="text-text-neutral-secondary size-5" />
          </button>
        )}
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align={align}
        className={cn(
          "border-border-neutral-secondary bg-bg-neutral-secondary w-56",
          className,
        )}
      >
        {label && (
          <>
            <DropdownMenuLabel>{label}</DropdownMenuLabel>
            <DropdownMenuSeparator />
          </>
        )}
        {children}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

interface ActionDropdownItemProps
  extends Omit<ComponentProps<typeof DropdownMenuItem>, "children"> {
  /** Icon displayed before the label */
  icon?: ReactNode;
  /** Main label text */
  label: ReactNode;
  /** Optional description text below the label */
  description?: string;
  /** Whether the item is destructive (danger styling) */
  destructive?: boolean;
}

export function ActionDropdownItem({
  icon,
  label,
  description,
  destructive = false,
  className,
  ...props
}: ActionDropdownItemProps) {
  return (
    <DropdownMenuItem
      className={cn(
        "flex cursor-pointer items-center gap-2",
        destructive && "text-destructive focus:text-destructive",
        className,
      )}
      {...props}
    >
      {icon && (
        <span
          className={cn(
            "text-muted-foreground shrink-0 [&>svg]:size-5",
            destructive && "text-destructive",
          )}
        >
          {icon}
        </span>
      )}
      <div className="flex flex-col">
        <span>{label}</span>
        {description && (
          <span
            className={cn(
              "text-muted-foreground text-xs",
              destructive && "text-destructive/70",
            )}
          >
            {description}
          </span>
        )}
      </div>
    </DropdownMenuItem>
  );
}

// Re-export commonly used components for convenience
export {
  DropdownMenuLabel as ActionDropdownLabel,
  DropdownMenuSeparator as ActionDropdownSeparator,
} from "./dropdown";
