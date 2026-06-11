"use client";

import * as TabsPrimitive from "@radix-ui/react-tabs";
import { motion, useReducedMotion } from "framer-motion";
import type { ComponentProps, ReactNode } from "react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";

/**
 * Trigger component style parts using semantic class names
 */
const TRIGGER_STYLES = {
  base: "relative inline-flex min-w-0 items-center justify-center gap-2 py-3 text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&:not(:first-child)]:pl-4 [&:not(:last-child)]:pr-4",
  border: "border-r border-border-neutral-secondary last:border-r-0",
  text: "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white",
  active:
    "data-[state=active]:text-slate-900 dark:data-[state=active]:text-white",
  underline:
    "after:absolute after:bottom-0 after:left-0 after:right-4 after:h-0.5 after:scale-x-0 after:bg-emerald-400 after:transition-transform data-[state=active]:after:scale-x-100 [&:not(:first-child)]:after:left-4 [&:last-child]:after:right-0",
  focus:
    "focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white focus-visible:outline-none dark:focus-visible:ring-offset-slate-950",
  icon: "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
} as const;

/**
 * Content component styles
 */
const CONTENT_STYLES =
  "mt-2 will-change-transform motion-reduce:transform-none focus-visible:rounded-md focus-visible:outline-1 focus-visible:ring-[3px] focus-visible:border-ring focus-visible:outline-ring focus-visible:ring-ring/50" as const;

/**
 * Build trigger className by combining style parts
 */
function buildTriggerClassName(): string {
  return [
    TRIGGER_STYLES.base,
    TRIGGER_STYLES.border,
    TRIGGER_STYLES.text,
    TRIGGER_STYLES.active,
    TRIGGER_STYLES.underline,
    TRIGGER_STYLES.focus,
    TRIGGER_STYLES.icon,
  ].join(" ");
}

/**
 * Build list className
 */
function buildListClassName(): string {
  // `flex` + `min-w-0` lets the triggers shrink proportionally when the
  // container is narrow, so each trigger truncates with ellipsis instead
  // of forcing a horizontal scrollbar.
  return "flex w-full min-w-0 items-center border-border-neutral-secondary";
}

function Tabs({
  className,
  ...props
}: ComponentProps<typeof TabsPrimitive.Root>) {
  return (
    <TabsPrimitive.Root
      data-slot="tabs"
      className={cn("w-full", className)}
      {...props}
    />
  );
}

function TabsList({
  className,
  ...props
}: ComponentProps<typeof TabsPrimitive.List>) {
  return (
    <TabsPrimitive.List
      data-slot="tabs-list"
      className={cn(buildListClassName(), className)}
      {...props}
    />
  );
}

interface TabsTriggerProps
  extends ComponentProps<typeof TabsPrimitive.Trigger> {
  /**
   * When set, the trigger is wrapped in a shadcn Tooltip rendered below
   * the bar. Useful for showing the full name when the label is truncated
   * to ellipsis on narrow containers.
   */
  tooltip?: ReactNode;
}

function TabsTrigger({
  className,
  tooltip,
  children,
  ...props
}: TabsTriggerProps) {
  const trigger = (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      className={cn(buildTriggerClassName(), className)}
      {...props}
    >
      {/* Wrapper provides the block-level box needed for `truncate` to
       * actually render an ellipsis. Padding and gap on the trigger stay
       * constant; only this span shrinks below its content width. */}
      <span className="block min-w-0 truncate">{children}</span>
    </TabsPrimitive.Trigger>
  );
  if (!tooltip) return trigger;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{trigger}</TooltipTrigger>
      <TooltipContent side="bottom">{tooltip}</TooltipContent>
    </Tooltip>
  );
}

function TabsContent({
  className,
  children,
  ...props
}: ComponentProps<typeof TabsPrimitive.Content>) {
  const shouldReduceMotion = useReducedMotion();

  return (
    <TabsPrimitive.Content asChild {...props}>
      <motion.div
        data-slot="tabs-content"
        initial={shouldReduceMotion ? false : { opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={
          shouldReduceMotion
            ? { duration: 0 }
            : { duration: 0.2, ease: "easeOut" }
        }
        className={cn(CONTENT_STYLES, className)}
      >
        {children}
      </motion.div>
    </TabsPrimitive.Content>
  );
}

export { Tabs, TabsContent, TabsList, TabsTrigger };
