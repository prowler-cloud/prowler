"use client";

import { useEffect, useState } from "react";

import { cn } from "@/lib";

import { useNavigationProgress } from "./use-navigation-progress";

/**
 * A top progress bar that shows during page navigation.
 * Renders at the very top of the viewport with fixed positioning.
 *
 * Navigation start is detected via onRouterTransitionStart in instrumentation-client.ts
 * Navigation end is detected via URL change in useNavigationProgress hook.
 */
export function NavigationProgress() {
  const { isLoading, progress } = useNavigationProgress();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (isLoading) {
      setVisible(true);
    } else {
      // Keep visible briefly after loading completes for smooth animation
      const timeout = setTimeout(() => setVisible(false), 200);
      return () => clearTimeout(timeout);
    }
  }, [isLoading]);

  if (!visible) return null;

  return (
    <div
      className="fixed top-0 left-0 z-[99999] h-[3px] w-full"
      role="progressbar"
      aria-valuenow={progress}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label="Page loading progress"
    >
      <div
        className={cn(
          "bg-button-primary h-full transition-all duration-200 ease-out",
          isLoading && "shadow-progress-glow",
        )}
        style={{ width: `${progress}%` }}
      />
    </div>
  );
}
