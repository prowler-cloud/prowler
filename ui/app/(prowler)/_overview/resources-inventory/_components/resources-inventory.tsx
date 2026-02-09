import Link from "next/link";

import { ResourceInventoryItem } from "@/actions/overview";
import { Card, CardContent, CardTitle } from "@/components/shadcn";

import { ResourcesInventoryCardItem } from "./resources-inventory-card-item";

interface ResourcesInventoryProps {
  items: ResourceInventoryItem[];
  filters?: Record<string, string | string[] | undefined>;
}

const MAX_VISIBLE_GROUPS = 8;

export function ResourcesInventory({
  items,
  filters,
}: ResourcesInventoryProps) {
  const isEmpty = items.length === 0;

  // Sort by failedFindings (desc), then by totalResources (desc) to prioritize groups with issues
  const sortedItems = [...items].sort((a, b) => {
    if (b.failedFindings !== a.failedFindings) {
      return b.failedFindings - a.failedFindings;
    }
    return b.totalResources - a.totalResources;
  });

  // Take top 8 most relevant groups
  const visibleItems = sortedItems.slice(0, MAX_VISIBLE_GROUPS);
  const firstRow = visibleItems.slice(0, 4);
  const secondRow = visibleItems.slice(4, 8);

  return (
    <Card variant="base" className="flex w-full flex-col">
      <div className="flex w-full items-center justify-between">
        <CardTitle>Resource Inventory</CardTitle>
        <Link
          href="/resources"
          className="text-button-tertiary hover:text-button-tertiary-hover text-sm font-medium transition-colors"
        >
          View All Resources
        </Link>
      </div>
      <CardContent className="mt-4 flex flex-col gap-3">
        {isEmpty ? (
          <div
            className="flex w-full items-center justify-center py-8"
            role="status"
          >
            <p className="text-text-neutral-tertiary text-sm">
              No resource inventory data available.
            </p>
          </div>
        ) : (
          <>
            {/* First row */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {firstRow.map((item) => (
                <ResourcesInventoryCardItem
                  key={item.id}
                  item={item}
                  filters={filters}
                />
              ))}
            </div>
            {/* Second row */}
            {secondRow.length > 0 && (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {secondRow.map((item) => (
                  <ResourcesInventoryCardItem
                    key={item.id}
                    item={item}
                    filters={filters}
                  />
                ))}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
