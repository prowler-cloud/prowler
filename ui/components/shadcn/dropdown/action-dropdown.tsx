"use client";

import { MoreHorizontal } from "lucide-react";
import { ComponentProps, ReactNode } from "react";

import { cn } from "@/lib/utils";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./dropdown";

interface ActionDropdownProps {
  /** The dropdown trigger element. Defaults to a vertical dots icon button */
  trigger?: ReactNode;
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
          "border-border-neutral-secondary bg-bg-neutral-secondary w-56 rounded-xl",
          className,
        )}
      >
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
        "hover:bg-bg-neutral-tertiary flex cursor-pointer items-start gap-2 rounded-md transition-colors",
        destructive &&
          "text-text-error-primary focus:text-text-error-primary hover:bg-destructive/10",
        className,
      )}
      {...props}
    >
      {icon && (
        <span
          className={cn(
            "text-muted-foreground mt-0.5 shrink-0 [&>svg]:size-4",
            destructive && "text-text-error-primary",
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
              destructive && "text-text-error-primary/70",
            )}
          >
            {description}
          </span>
        )}
      </div>
    </DropdownMenuItem>
  );
}

export function ActionDropdownDangerZone({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <>
      <DropdownMenuSeparator />
      <span className="text-text-neutral-tertiary px-2 py-1.5 text-xs">
        Danger zone
      </span>
      {children}
    </>
  );
}
