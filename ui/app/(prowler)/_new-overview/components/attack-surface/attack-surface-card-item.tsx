import { CircleAlert } from "lucide-react";

import { AttackSurfaceItem } from "@/actions/overview";
import { Card, CardContent } from "@/components/shadcn";

interface AttackSurfaceCardItemProps {
  item: AttackSurfaceItem;
}

export function AttackSurfaceCardItem({ item }: AttackSurfaceCardItemProps) {
  return (
    <Card
      variant="inner"
      padding="md"
      className="relative flex min-h-[120px] min-w-[200px] flex-1 flex-col justify-between"
      aria-label={`${item.label}: ${item.failedFindings} failed findings`}
    >
      {item.hasFailures && (
        <CircleAlert
          size={20}
          className="text-text-error-primary absolute top-3 right-3"
          aria-label="Has failed findings"
        />
      )}
      <CardContent className="flex flex-col gap-2 p-0">
        <span
          className="text-5xl leading-none font-light tracking-tight"
          aria-hidden="true"
        >
          {item.failedFindings}
        </span>
        <span className="text-text-neutral-tertiary text-sm leading-6">
          {item.label}
        </span>
      </CardContent>
    </Card>
  );
}
