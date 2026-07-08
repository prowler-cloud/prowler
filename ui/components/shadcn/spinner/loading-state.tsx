"use client";

import { cn } from "@/lib/utils";

import { Spinner } from "./spinner";

interface LoadingStateProps {
  label?: string;
  className?: string;
  spinnerClassName?: string;
}

export function LoadingState({
  label,
  className,
  spinnerClassName,
}: LoadingStateProps) {
  return (
    <div
      className={cn("flex items-center justify-center gap-2 py-8", className)}
    >
      <Spinner className={cn("size-6", spinnerClassName)} />
      {label && (
        <span className="text-text-neutral-tertiary text-sm">{label}</span>
      )}
    </div>
  );
}
