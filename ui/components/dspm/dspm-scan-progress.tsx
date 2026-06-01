"use client";

import { Check } from "lucide-react";

import { Spinner } from "@/components/shadcn/spinner/spinner";
import { cn } from "@/lib/utils";

export type ScanStatus =
  | "discovering"
  | "sampling"
  | "classifying"
  | "done";

interface Step {
  key: Exclude<ScanStatus, "done">;
  label: string;
}

const STEPS: Step[] = [
  { key: "discovering", label: "Discovering datastores" },
  { key: "sampling", label: "Sampling content" },
  { key: "classifying", label: "Classifying with Lighthouse AI" },
];

const STATUS_ORDER: Record<ScanStatus, number> = {
  discovering: 0,
  sampling: 1,
  classifying: 2,
  done: 3,
};

interface DspmScanProgressProps {
  status: ScanStatus;
}

export const DspmScanProgress = ({ status }: DspmScanProgressProps) => {
  const currentIndex = STATUS_ORDER[status];

  return (
    <ol className="flex flex-col gap-3">
      {STEPS.map((step, index) => {
        const isComplete = index < currentIndex;
        const isActive = index === currentIndex;
        return (
          <li
            key={step.key}
            className={cn(
              "flex items-center gap-3 text-sm",
              isActive && "text-text-neutral-primary font-medium",
              isComplete && "text-text-neutral-secondary",
              !isActive && !isComplete && "text-text-neutral-tertiary",
            )}
          >
            <span className="flex size-5 shrink-0 items-center justify-center">
              {isComplete ? (
                <Check className="text-bg-data-low size-5" />
              ) : isActive ? (
                <Spinner className="size-5" />
              ) : (
                <span className="bg-bg-neutral-tertiary size-2.5 rounded-full" />
              )}
            </span>
            <span>{step.label}</span>
          </li>
        );
      })}
    </ol>
  );
};
