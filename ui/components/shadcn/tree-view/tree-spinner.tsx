"use client";

import { cn } from "@/lib/utils";

interface TreeSpinnerProps {
  className?: string;
}

/**
 * TreeSpinner component - a circular loading indicator for tree nodes.
 *
 * Features:
 * - 20x20 (size-5) default size to match checkbox sm
 * - 2.5px stroke for good visibility
 * - Uses button-primary color
 * - Smooth rotation animation
 */
export function TreeSpinner({ className }: TreeSpinnerProps) {
  return (
    <svg
      className={cn("size-5 shrink-0 animate-spin", className)}
      viewBox="0 0 20 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="Loading"
    >
      {/* Background track */}
      <circle
        cx="10"
        cy="10"
        r="7.5"
        className="stroke-button-primary/20"
        strokeWidth="2.5"
        fill="none"
      />
      {/* Animated arc */}
      <circle
        cx="10"
        cy="10"
        r="7.5"
        className="stroke-button-primary"
        strokeWidth="2.5"
        fill="none"
        strokeLinecap="round"
        strokeDasharray="47.12"
        strokeDashoffset="35.34"
      />
    </svg>
  );
}
