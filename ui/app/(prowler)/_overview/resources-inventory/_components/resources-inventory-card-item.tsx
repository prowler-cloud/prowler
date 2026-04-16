import { Bell, ShieldCheck, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { ResourceInventoryItem } from "@/actions/overview";
import { CardVariant, ResourceStatsCard, StatItem } from "@/components/shadcn";
import { cn } from "@/lib/utils";

interface ResourcesInventoryCardItemProps {
  item: ResourceInventoryItem;
  filters?: Record<string, string | string[] | undefined>;
}

export function ResourcesInventoryCardItem({
  item,
  filters = {},
}: ResourcesInventoryCardItemProps) {
  const hasFailedFindings = item.failedFindings > 0;
  const hasResources = item.totalResources > 0;
  const resourceCardClassName = cn(
    "relative flex-1 overflow-hidden border-border-neutral-secondary bg-bg-neutral-secondary shadow-sm transition-[transform,border-color,background-color,box-shadow] duration-200",
    hasResources &&
      "hover:-translate-y-0.5 hover:shadow-md focus-visible:border-border-neutral-primary",
    hasFailedFindings
      ? "before:bg-bg-fail-primary hover:border-border-error-primary before:absolute before:inset-x-0 before:top-0 before:h-1"
      : hasResources
        ? "before:bg-bg-pass-primary hover:border-border-neutral-primary before:absolute before:inset-x-0 before:top-0 before:h-1"
        : "",
  );

  // Build URL with current filters + resource group specific filters
  const buildResourcesUrl = () => {
    if (!hasResources) return null;

    const params = new URLSearchParams();

    // Add group specific filter
    params.set("filter[groups__in]", item.id);

    // Add current page filters (provider, account, etc.)
    // Transform provider_id__in to provider__in for resources endpoint
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && !params.has(key)) {
        const transformedKey =
          key === "filter[provider_id__in]" ? "filter[provider__in]" : key;
        params.set(transformedKey, String(value));
      }
    });

    return `/resources?${params.toString()}`;
  };

  const resourcesUrl = buildResourcesUrl();

  // Build stats array for the card content
  const stats: StatItem[] = [];
  if (hasFailedFindings && item.newFailedFindings > 0) {
    stats.push({
      icon: Bell,
      label: `${item.newFailedFindings} New`,
    });
  }

  // Empty state when no resources
  if (!hasResources) {
    const cardContent = (
      <ResourceStatsCard
        header={{
          icon: item.icon,
          title: item.label,
          resourceCount: `${item.totalResources.toLocaleString()} Resources`,
        }}
        emptyState={{
          message: "No Findings to display",
        }}
        className={resourceCardClassName}
      />
    );

    return cardContent;
  }

  // Card with findings data
  const cardContent = (
    <ResourceStatsCard
      header={{
        icon: item.icon,
        title: item.label,
        resourceCount: `${item.totalResources.toLocaleString()} Resources`,
      }}
      badge={{
        icon: hasFailedFindings ? TriangleAlert : ShieldCheck,
        count: item.failedFindings,
        variant: hasFailedFindings ? CardVariant.fail : CardVariant.pass,
      }}
      label="Fail Findings"
      stats={stats}
      variant={CardVariant.default}
      className={cn(resourceCardClassName, hasResources && "cursor-pointer")}
    />
  );

  if (resourcesUrl) {
    return (
      <Link
        href={resourcesUrl}
        className="focus-visible:ring-border-neutral-primary/40 flex flex-1 rounded-[12px] focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none"
      >
        {cardContent}
      </Link>
    );
  }

  return cardContent;
}
