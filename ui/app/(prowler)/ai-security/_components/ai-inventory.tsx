import Link from "next/link";

import { aiResourcesHref } from "@/app/(prowler)/ai-security/_lib/findings";
import type { AiInventoryItem } from "@/app/(prowler)/ai-security/_types";
import { Button, Card, CardContent } from "@/components/shadcn";

import { SectionHeader } from "./section-header";

/** What the AI checks looked at, by kind of resource, with its main problem. */
export function AiInventory({ items }: { items: AiInventoryItem[] }) {
  const total = items.reduce((sum, item) => sum + item.count, 0);

  return (
    <Card variant="base" className="w-full min-w-0">
      <SectionHeader
        title="AI inventory"
        description={`${total.toLocaleString()} resources the AI checks evaluated in the last scan.`}
        aside={
          <Button asChild variant="link" size="link-sm">
            <Link href={aiResourcesHref()}>Open in Resources</Link>
          </Button>
        }
      />
      <CardContent>
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {items.map((item) => (
            <li key={item.resourceType} className="min-w-0">
              <Link
                href={aiResourcesHref({
                  "filter[type__in]": item.resourceType,
                })}
                className="focus-visible:ring-ring/50 block h-full rounded-[12px] focus-visible:ring-2 focus-visible:outline-none"
              >
                <Card
                  variant="inner"
                  padding="md"
                  interactive
                  className="h-full gap-0.5"
                >
                  <span className="text-text-neutral-primary flex items-baseline gap-2 text-sm font-medium">
                    <span className="text-xl font-semibold tabular-nums">
                      {item.count.toLocaleString()}
                    </span>
                    {item.label}
                  </span>
                  <span className="text-text-neutral-tertiary text-xs">
                    {item.providers}
                  </span>
                  <span className="text-text-error-primary text-xs font-medium">
                    {item.issue}
                  </span>
                </Card>
              </Link>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
