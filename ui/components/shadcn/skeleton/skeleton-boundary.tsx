import { ReactNode, Suspense } from "react";

import { SkeletonContentReveal } from "./skeleton-content-reveal";

interface SkeletonBoundaryProps {
  children: ReactNode;
  fallback: ReactNode;
  className?: string;
}

function SkeletonBoundary({
  children,
  fallback,
  className,
}: SkeletonBoundaryProps) {
  return (
    <Suspense fallback={fallback}>
      <SkeletonContentReveal className={className}>
        {children}
      </SkeletonContentReveal>
    </Suspense>
  );
}

export { SkeletonBoundary };
