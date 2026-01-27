"use client";

import { cn } from "@/lib/utils";

interface TreeSpinnerProps {
  className?: string;
}

/**
 * TreeSpinner component - a circular loading indicator for tree nodes.
 *
 * Features:
 * - 24x24 size with 2px stroke
 * - Uses button-primary color
 * - Smooth rotation animation
 */
export function TreeSpinner({ className }: TreeSpinnerProps) {
  return (
    <svg
      className={cn("size-6 shrink-0 animate-spin", className)}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="Loading"
    >
      {/* Background track */}
      <circle
        cx="12"
        cy="12"
        r="10"
        className="stroke-button-primary/20"
        strokeWidth="2"
        fill="none"
      />
      {/* Animated arc */}
      <circle
        cx="12"
        cy="12"
        r="10"
        className="stroke-button-primary"
        strokeWidth="2"
        fill="none"
        strokeLinecap="round"
        strokeDasharray="62.83"
        strokeDashoffset="47.12"
      />
    </svg>
  );
}
