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
      className={cn(
        "animate-in fade-in-0 flex items-center justify-center gap-2 py-8 duration-200 ease-out motion-reduce:animate-none motion-reduce:transition-none",
        className,
      )}
    >
      <Spinner className={cn("size-6", spinnerClassName)} />
      {label && (
        <span className="text-text-neutral-tertiary text-sm transition-colors duration-200 ease-out motion-reduce:transition-none">
          {label}
        </span>
      )}
    </div>
  );
}
