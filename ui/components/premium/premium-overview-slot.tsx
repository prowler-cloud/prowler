import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { PremiumBadge } from "@/components/shared/premium-badge";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

interface PremiumOverviewSlotProps {
  title: string;
  description: string;
  className?: string;
}

const PLACEHOLDER_ROWS = [80, 64, 72, 48] as const;

export function PremiumOverviewSlot({
  title,
  description,
  className,
}: PremiumOverviewSlotProps) {
  return (
    <Card variant="base" className={className}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <h3 className="text-text-neutral-primary text-sm font-medium">
            {title}
          </h3>
          <PremiumBadge
            feature={CLOUD_UPGRADE_FEATURE.EXPLOITABILITY_ISSUES}
            compact
          />
        </div>
        <span className="text-text-neutral-tertiary text-[10px] font-semibold tracking-[0.14em]">
          SAMPLE DATA
        </span>
      </div>
      <CardContent className="relative mt-4 flex flex-1 flex-col gap-3">
        <div aria-hidden="true" className="flex flex-col gap-3 blur-sm">
          {PLACEHOLDER_ROWS.map((width) => (
            <div
              key={width}
              className="bg-bg-neutral-tertiary h-10 rounded-lg"
              style={{ width: `${width}%` }}
            />
          ))}
        </div>
        <div className="border-border-neutral-secondary bg-bg-neutral-primary absolute inset-x-0 bottom-0 flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-text-neutral-secondary text-xs">{description}</p>
          <Button asChild size="sm">
            <Link href="/issues">See how it works</Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
