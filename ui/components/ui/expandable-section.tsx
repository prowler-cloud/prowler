"use client";

import { cn } from "@/lib/utils";

interface ExpandableSectionProps {
  isExpanded: boolean;
  children: React.ReactNode;
  className?: string;
}

/**
 * Animated expandable section using CSS grid for smooth height transitions.
 * Animates from height 0 to auto content height.
 */
export function ExpandableSection({
  isExpanded,
  children,
  className,
}: ExpandableSectionProps) {
  return (
    <div
      className={cn(
        "grid transition-[grid-template-rows] duration-300 ease-in-out",
        isExpanded ? "grid-rows-[1fr]" : "grid-rows-[0fr]",
        className,
      )}
    >
      <div className="overflow-hidden">
        <div className={cn("pt-4", !isExpanded && "invisible")}>{children}</div>
      </div>
    </div>
  );
}
