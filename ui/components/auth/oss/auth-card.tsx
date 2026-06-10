import { ReactNode } from "react";

import { cn } from "@/lib";

interface AuthCardProps {
  className?: string;
  children: ReactNode;
}

const CARD_BASE =
  "relative isolate flex w-full flex-col overflow-hidden rounded-3xl border border-black/8 bg-gradient-to-br from-white/78 via-white/70 to-white/58 shadow-2xl shadow-slate-300/35 ring-1 ring-white/55 backdrop-blur-2xl before:pointer-events-none before:absolute before:inset-0 before:bg-gradient-to-br before:from-white/55 before:via-white/10 before:to-transparent before:content-[''] after:pointer-events-none after:absolute after:-top-16 after:right-10 after:h-36 after:w-36 after:rounded-full after:bg-emerald-400/8 after:blur-3xl after:content-[''] dark:border-white/10 dark:from-black/72 dark:via-black/64 dark:to-black/56 dark:shadow-black/45 dark:ring-white/6 dark:before:from-white/8 dark:before:via-transparent";

export const AuthCard = ({ className, children }: AuthCardProps) => (
  <div className={cn(CARD_BASE, className)}>{children}</div>
);
