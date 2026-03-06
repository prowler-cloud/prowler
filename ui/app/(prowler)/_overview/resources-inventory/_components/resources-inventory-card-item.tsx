import { Bell, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { ResourceInventoryItem } from "@/actions/overview";
import { CardVariant, ResourceStatsCard, StatItem } from "@/components/shadcn";

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
          resourceCount: item.totalResources,
        }}
        emptyState={{
          message: "No Findings to display",
        }}
        className="flex-1"
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
        resourceCount: item.totalResources,
      }}
      badge={{
        icon: TriangleAlert,
        count: item.failedFindings,
        variant: CardVariant.fail,
      }}
      label="Fail Findings"
      stats={stats}
      variant={hasFailedFindings ? CardVariant.fail : CardVariant.default}
      className={
        hasFailedFindings
          ? "hover:border-bg-fail/60 flex-1 cursor-pointer transition-all"
          : "flex-1"
      }
    />
  );

  if (resourcesUrl) {
    return (
      <Link href={resourcesUrl} className="flex flex-1">
        {cardContent}
      </Link>
    );
  }

  return cardContent;
}
