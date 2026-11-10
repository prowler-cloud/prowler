import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface FitTextProps {
  children: ReactNode;
  className?: string;
}

/** One line that shrinks with its table column instead of widening it. */
export function FitText({ children, className }: FitTextProps) {
  return (
    <span className={cn("line-clamp-1 break-all", className)}>{children}</span>
  );
}
