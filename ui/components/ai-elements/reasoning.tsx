"use client";

import { ChevronDown } from "lucide-react";
import * as React from "react";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible/collapsible";
import { cn } from "@/lib/utils";

// ============================================================================
// Reasoning Component - Collapsible AI reasoning display
// ============================================================================

interface ReasoningProps
  extends React.ComponentPropsWithoutRef<typeof Collapsible> {
  /**
   * Controls whether reasoning panel is open during streaming
   * Automatically opens when AI is generating reasoning content
   */
  isStreaming?: boolean;
  className?: string;
  children?: React.ReactNode;
}

const Reasoning = React.forwardRef<
  React.ElementRef<typeof Collapsible>,
  ReasoningProps
>(({ isStreaming = false, className, children, ...props }, ref) => {
  return (
    <Collapsible
      ref={ref}
      open={isStreaming}
      className={cn("bg-muted/50 rounded-lg border p-4", className)}
      {...props}
    >
      {children}
    </Collapsible>
  );
});
Reasoning.displayName = "Reasoning";

// ============================================================================
// ReasoningTrigger - Toggle button for reasoning panel
// ============================================================================

interface ReasoningTriggerProps
  extends React.ComponentPropsWithoutRef<typeof CollapsibleTrigger> {
  title?: string;
  className?: string;
}

const ReasoningTrigger = React.forwardRef<
  React.ElementRef<typeof CollapsibleTrigger>,
  ReasoningTriggerProps
>(({ title = "Reasoning", className, children, ...props }, ref) => {
  return (
    <CollapsibleTrigger
      ref={ref}
      className={cn(
        "flex w-full items-center justify-between text-sm font-medium transition-all hover:underline [&[data-state=open]>svg]:rotate-180",
        className,
      )}
      {...props}
    >
      <span>{title}</span>
      <ChevronDown className="h-4 w-4 transition-transform duration-200" />
      {children}
    </CollapsibleTrigger>
  );
});
ReasoningTrigger.displayName = "ReasoningTrigger";

// ============================================================================
// ReasoningContent - Content area for reasoning text
// ============================================================================

interface ReasoningContentProps
  extends React.ComponentPropsWithoutRef<typeof CollapsibleContent> {
  className?: string;
}

const ReasoningContent = React.forwardRef<
  React.ElementRef<typeof CollapsibleContent>,
  ReasoningContentProps
>(({ className, children, ...props }, ref) => {
  return (
    <CollapsibleContent
      ref={ref}
      className={cn(
        "data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down mt-2 overflow-hidden text-sm transition-all",
        className,
      )}
      {...props}
    >
      <div className="prose prose-sm dark:prose-invert max-w-none pt-2">
        {children}
      </div>
    </CollapsibleContent>
  );
});
ReasoningContent.displayName = "ReasoningContent";

export { Reasoning, ReasoningContent, ReasoningTrigger };
