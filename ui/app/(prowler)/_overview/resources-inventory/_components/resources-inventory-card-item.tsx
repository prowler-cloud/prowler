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
  const accent = hasFailedFindings ? CardVariant.fail : CardVariant.pass;

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

  const header = {
    icon: item.icon,
    title: item.label,
    resourceCount: `${item.totalResources.toLocaleString()} Resources`,
  };

  if (!hasResources) {
    return (
      <ResourceStatsCard
        header={header}
        emptyState={{ message: "No Findings to display" }}
        className="flex-1"
      />
    );
  }

  const cardContent = (
    <ResourceStatsCard
      header={header}
      badge={{
        icon: hasFailedFindings ? TriangleAlert : ShieldCheck,
        count: item.failedFindings,
        variant: hasFailedFindings ? CardVariant.fail : CardVariant.pass,
      }}
      label="Fail Findings"
      stats={stats}
      accent={accent}
      className={cn(
        "flex-1 cursor-pointer shadow-sm transition-[transform,border-color,box-shadow] duration-200",
        "hover:-translate-y-0.5 hover:shadow-md",
        hasFailedFindings
          ? "hover:border-border-error-primary"
          : "hover:border-border-neutral-primary",
      )}
    />
  );

  if (resourcesUrl) {
    return (
      <Link
        href={resourcesUrl}
        className="focus-visible:ring-border-neutral-primary/40 flex flex-1 rounded-xl focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none"
      >
        {cardContent}
      </Link>
    );
  }

  return cardContent;
}
