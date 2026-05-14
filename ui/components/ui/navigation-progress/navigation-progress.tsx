"use client";

import { useEffect, useState } from "react";

import { cn } from "@/lib";

import { useNavigationProgress } from "./use-navigation-progress";

const HIDE_DELAY_MS = 200;

export function NavigationProgress() {
  const { isLoading, progress } = useNavigationProgress();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (isLoading) return setVisible(true);

    const timeout = setTimeout(() => setVisible(false), HIDE_DELAY_MS);
    return () => clearTimeout(timeout);
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
