import Link from "next/link";

import { AttackSurfaceItem } from "@/actions/overview";
import { Card, CardContent } from "@/components/shadcn";
import { mapProviderFiltersForFindings } from "@/lib";

interface AttackSurfaceCardItemProps {
  item: AttackSurfaceItem;
  filters?: Record<string, string | string[] | undefined>;
}

export function AttackSurfaceCardItem({
  item,
  filters = {},
}: AttackSurfaceCardItemProps) {
  const hasCheckIds = item.checkIds.length > 0;

  // Build URL with current filters + attack surface specific filters
  const buildFindingsUrl = () => {
    if (!hasCheckIds) return null;

    const params = new URLSearchParams();

    // Add attack surface specific filters
    params.set("filter[check_id__in]", item.checkIds.join(","));
    params.set("filter[status__in]", "FAIL");
    params.set("filter[muted]", "false");

    // Add current page filters (provider, account, etc.)
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && !params.has(key)) {
        params.set(key, String(value));
      }
    });

    // Map provider filters for findings page compatibility
    mapProviderFiltersForFindings(params);

    return `/findings?${params.toString()}`;
  };

  const findingsUrl = buildFindingsUrl();

  const hasFindings = item.failedFindings > 0;

  const getCardStyles = () => {
    if (!hasCheckIds) {
      return "opacity-50 cursor-not-allowed";
    }
    if (hasFindings) {
      return "cursor-pointer border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.2)] transition-all hover:border-rose-500/60 hover:shadow-[0_0_16px_rgba(244,63,94,0.3)]";
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

  if (findingsUrl) {
    return (
      <Link href={findingsUrl} className="flex min-w-[200px] flex-1">
        {cardContent}
      </Link>
    );
  }

  return cardContent;
}
