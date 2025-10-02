"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

// ============================================================================
// Loader Component - Loading spinner for AI operations
// ============================================================================

interface LoaderProps extends React.HTMLAttributes<HTMLDivElement> {
  /**
   * Size of the loader spinner
   * @default "default"
   */
  size?: "sm" | "default" | "lg";
  /**
   * Optional loading text to display
   */
  text?: string;
  className?: string;
}

const loaderSizes = {
  sm: "h-4 w-4 border-2",
  default: "h-6 w-6 border-2",
  lg: "h-8 w-8 border-3",
};

const Loader = React.forwardRef<HTMLDivElement, LoaderProps>(
  ({ size = "default", text, className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn("flex items-center gap-2", className)}
        role="status"
        aria-live="polite"
        aria-label={text || "Loading"}
        {...props}
      >
        <div
          className={cn(
            "border-prowler-green animate-spin rounded-full border-t-transparent",
            loaderSizes[size],
          )}
        />
        {text && <span className="text-muted-foreground text-sm">{text}</span>}
        <span className="sr-only">{text || "Loading..."}</span>
      </div>
    );
  },
);
Loader.displayName = "Loader";

export { Loader };
