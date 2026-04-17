import { ReactNode } from "react";

import { cn } from "@/lib";

interface AuthCardProps {
  className?: string;
  children: ReactNode;
}

const CARD_BASE =
  "rounded-large border-divider shadow-small dark:bg-background/80 relative flex w-full flex-col border bg-white/85 backdrop-blur-xl";

export const AuthCard = ({ className, children }: AuthCardProps) => (
  <div className={cn(CARD_BASE, className)}>{children}</div>
);
