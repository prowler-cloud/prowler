"use client";

import { EllipsisVertical } from "lucide-react";
import { ComponentProps, ReactNode, useEffect, useState } from "react";

import { cn } from "@/lib/utils";

import { Tooltip, TooltipContent, TooltipTrigger } from "../tooltip";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  type DropdownContentVariant,
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
  /** Content style variant, e.g. the Lighthouse gradient border */
  menuVariant?: DropdownContentVariant;
  /** Accessible label for the trigger */
  ariaLabel?: string;
  /** Controlled open state. Omit for the default uncontrolled behavior. */
  open?: boolean;
  /** Open-state change notifications; pairs with `open` for controlled use. */
  onOpenChange?: (open: boolean) => void;
  children: ReactNode;
}

export function ActionDropdown({
  trigger,
  variant = "table",
  align = "end",
  className,
  menuVariant,
  ariaLabel = "Open actions menu",
  open: openProp,
  onOpenChange,
  children,
}: ActionDropdownProps) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false);
  const open = openProp ?? uncontrolledOpen;

  const setOpen = (next: boolean) => {
    if (openProp === undefined) setUncontrolledOpen(next);
    onOpenChange?.(next);
  };

  // Close dropdown when any ancestor scrolls (capture phase catches all scroll
  // events), but ignore scrolls originating inside a nested dialog (e.g.
  // pasting into a modal textarea) or inside the menu's own content, so they
  // don't unmount what the user is interacting with.
  useEffect(() => {
    if (!open) return;
    const handleScroll = (event: Event) => {
      const target = event.target;
      if (
        target instanceof Element &&
        target.closest(
          '[data-slot="dialog-content"], [data-slot="dropdown-menu-content"]',
        )
      ) {
        return;
      }
      if (openProp === undefined) setUncontrolledOpen(false);
      onOpenChange?.(false);
    };
    window.addEventListener("scroll", handleScroll, true);
    return () => window.removeEventListener("scroll", handleScroll, true);
  }, [open, openProp, onOpenChange]);

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
        variant={menuVariant}
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
  /** Tooltip shown while the item remains interactive. */
  tooltip?: string;
  /** Tooltip shown when the item is disabled. */
  disabledTooltip?: string;
}

export function ActionDropdownItem({
  icon,
  label,
  description,
  destructive = false,
  className,
  tooltip,
  disabledTooltip,
  disabled,
  onSelect,
  ...props
}: ActionDropdownItemProps) {
  const item = (
    <DropdownMenuItem
      className={cn(
        "hover:bg-border-neutral-secondary flex cursor-pointer items-start gap-2 rounded-lg transition-colors",
        destructive &&
          "text-text-error-primary focus:text-text-error-primary hover:bg-destructive/10",
        // A disabled item with a tooltip stays interactive so hover can fire,
        // which means Radix never stamps data-disabled — mirror its disabled
        // styling manually.
        disabled &&
          "cursor-not-allowed opacity-50 hover:bg-transparent focus:bg-transparent",
        className,
      )}
      aria-disabled={disabled || undefined}
      disabled={disabled && !disabledTooltip}
      onSelect={(event) => {
        if (disabled) {
          event.preventDefault();
          return;
        }

        onSelect?.(event);
      }}
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

  const tooltipContent = tooltip ?? (disabled ? disabledTooltip : undefined);

  if (tooltipContent) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{item}</TooltipTrigger>
        <TooltipContent>{tooltipContent}</TooltipContent>
      </Tooltip>
    );
  }

  return item;
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
