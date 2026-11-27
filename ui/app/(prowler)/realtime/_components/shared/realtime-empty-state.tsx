import type { ReactNode } from "react";

import { Card } from "@/components/shadcn";

interface RealtimeEmptyStateProps {
  title: string;
  description: string;
  action?: ReactNode;
}

/** A panel with nothing to show yet, and what to do about it. */
export function RealtimeEmptyState({
  title,
  description,
  action,
}: RealtimeEmptyStateProps) {
  return (
    <Card variant="base" className="items-start gap-3 py-6">
      <div className="flex flex-col gap-1">
        <p className="text-text-neutral-primary text-sm font-semibold">
          {title}
        </p>
        <p className="text-text-neutral-tertiary max-w-2xl text-sm">
          {description}
        </p>
      </div>
      {action}
    </Card>
  );
}
