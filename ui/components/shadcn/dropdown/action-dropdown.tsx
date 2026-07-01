"use client";

import { EllipsisVertical } from "lucide-react";
import { ComponentProps, ReactNode, useEffect, useState } from "react";

import { cn } from "@/lib/utils";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./dropdown";

const ACTION_TRIGGER_STYLES = {
  table: "hover:bg-bg-neutral-tertiary rounded-full p-1 transition-colors",
  bordered: "hover:bg-bg-neutral-tertiary rounded-md p-1.5 transition-colors",
} as const;

type ActionDropdownVariant = keyof typeof ACTION_TRIGGER_STYLES;

interface ActionDropdownProps {
  /** The dropdown trigger element. Defaults to a vertical dots icon button */
  trigger?: ReactNode;
  /** Trigger style variant. "table" = compact pill, "bordered" = card action */
  variant?: ActionDropdownVariant;
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
  variant = "table",
  align = "end",
  className,
  ariaLabel = "Open actions menu",
  children,
}: ActionDropdownProps) {
  const [open, setOpen] = useState(false);

  // Close dropdown when any ancestor scrolls (capture phase catches all scroll events)
  useEffect(() => {
    if (!open) return;
    const handleScroll = () => setOpen(false);
    window.addEventListener("scroll", handleScroll, true);
    return () => window.removeEventListener("scroll", handleScroll, true);
  }, [open]);

  return (
    <DropdownMenu modal={false} open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        {trigger ?? (
          <button
            type="button"
            aria-label={ariaLabel}
            className={ACTION_TRIGGER_STYLES[variant]}
          >
            <EllipsisVertical
              className={cn(
                "text-text-neutral-secondary",
                variant === "bordered" ? "size-5" : "size-6",
              )}
            />
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
