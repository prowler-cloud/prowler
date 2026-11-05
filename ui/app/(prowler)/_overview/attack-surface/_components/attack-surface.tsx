import { AttackSurfaceItem } from "@/actions/overview";
import { Card, CardContent, CardTitle } from "@/components/shadcn";

import { AttackSurfaceCardItem } from "./attack-surface-card-item";

interface AttackSurfaceProps {
  items: AttackSurfaceItem[];
  filters?: Record<string, string | string[] | undefined>;
}

export function AttackSurface({ items, filters }: AttackSurfaceProps) {
  const isEmpty = items.length === 0;

  return (
    <Card variant="base" className="flex w-full flex-col">
      <CardTitle>Attack Surface</CardTitle>
      <CardContent className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {isEmpty ? (
          <div
            className="col-span-full flex w-full items-center justify-center py-8"
            role="status"
          >
            <p className="text-text-neutral-tertiary text-sm">
              No attack surface data available.
            </p>
          </div>
        ) : (
          items.map((item) => (
            <AttackSurfaceCardItem
              key={item.id}
              item={item}
              filters={filters}
            />
          ))
        )}
      </CardContent>
    </Card>
  );
}
