import { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface SkeletonContentRevealProps {
  children: ReactNode;
  className?: string;
}

function SkeletonContentReveal({
  children,
  className,
}: SkeletonContentRevealProps) {
  return (
    <div
      data-testid="skeleton-content-reveal"
      data-motion="skeleton-content-handoff"
      className={cn(
        "translate-y-0 opacity-100 transition-[opacity,transform] duration-700 ease-[cubic-bezier(0.16,1,0.3,1)] motion-reduce:transform-none motion-reduce:transition-none starting:translate-y-3 starting:opacity-0",
        className,
      )}
    >
      {children}
    </div>
  );
}

export { SkeletonContentReveal };
