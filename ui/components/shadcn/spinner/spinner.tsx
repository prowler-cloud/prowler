"use client";

import { cn } from "@/lib/utils";

interface SpinnerProps {
  className?: string;
}

/**
 * Spinner component - a circular loading indicator.
 *
 * Features:
 * - 20x20 (size-5) default size
 * - 2.5px stroke for good visibility
 * - Uses button-primary color
 * - Smooth rotation animation
 * - Accepts className to override size (e.g. "size-6", "size-4")
 */
export function Spinner({ className }: SpinnerProps) {
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
