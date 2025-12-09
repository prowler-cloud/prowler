import { Bell, Settings, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { ResourceInventoryItem } from "@/actions/overview";
import { CardVariant, ResourceStatsCard, StatItem } from "@/components/shadcn";
import { mapProviderFiltersForFindings } from "@/lib";

interface ResourcesInventoryCardItemProps {
  item: ResourceInventoryItem;
  filters?: Record<string, string | string[] | undefined>;
}

export function ResourcesInventoryCardItem({
  item,
  filters = {},
}: ResourcesInventoryCardItemProps) {
  const hasFindings = item.failedFindings > 0;
  const hasResources = item.totalResources > 0;

  // Build URL with current filters + resource type specific filters
  const buildFindingsUrl = () => {
    if (!hasFindings) return null;

    const params = new URLSearchParams();

    // Add resource type specific filters
    params.set("filter[resource_type]", item.id);
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

  // Build stats array for the card content
  const stats: StatItem[] = [];
  if (hasFindings) {
    stats.push({
      icon: Bell,
      label: `${item.newFindings} New`,
    });
    stats.push({
      icon: Settings,
      label: `${item.misconfigurations} Misconfigurations`,
    });
  }

  // Empty state when no resources or no findings
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
      variant={hasFindings ? CardVariant.fail : CardVariant.default}
      className={
        hasFindings
          ? "flex-1 cursor-pointer transition-all hover:border-rose-500/60"
          : "flex-1"
      }
    />
  );

  if (findingsUrl) {
    return (
      <Link href={findingsUrl} className="flex flex-1">
        {cardContent}
      </Link>
    );
  }

  return cardContent;
}
