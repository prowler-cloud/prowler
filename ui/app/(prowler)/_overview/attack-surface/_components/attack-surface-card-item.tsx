import Link from "next/link";

import { AttackSurfaceItem } from "@/actions/overview";
import { Card, CardContent } from "@/components/shadcn";

interface AttackSurfaceCardItemProps {
  item: AttackSurfaceItem;
  filters?: Record<string, string | string[] | undefined>;
}

export function AttackSurfaceCardItem({
  item,
  filters = {},
}: AttackSurfaceCardItemProps) {
  // Build URL with current filters + attack surface specific filters
  const buildFindingsUrl = () => {
    const params = new URLSearchParams();

    // Add attack surface category filter
    params.set("filter[category__in]", item.id);
    params.set("filter[status__in]", "FAIL");
    params.set("filter[muted]", "false");

    // Add current page filters (provider, account, etc.)
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && !params.has(key)) {
        params.set(key, String(value));
      }
    });

    return `/findings?${params.toString()}`;
  };

  const findingsUrl = buildFindingsUrl();

  const hasFindings = item.failedFindings > 0;

  const getCardStyles = () => {
    if (hasFindings) {
      return "cursor-pointer border-rose-500/40 shadow-rose-500/20 shadow-lg transition-all hover:border-rose-500/60 hover:shadow-rose-500/30";
    }
    return "cursor-pointer transition-colors hover:bg-accent";
  };

  const cardContent = (
    <Card
      variant="inner"
      padding="md"
      className={`flex min-h-[120px] min-w-[200px] flex-1 flex-col justify-between ${getCardStyles()}`}
      aria-label={`${item.label}: ${item.failedFindings} failed findings`}
    >
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

  return (
    <Link href={findingsUrl} className="flex min-w-[200px] flex-1">
      {cardContent}
    </Link>
  );
}
