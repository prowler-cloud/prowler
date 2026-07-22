import { getCompliancesOverview } from "@/actions/compliances";
import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { Accordion } from "@/components/shadcn/accordion/Accordion";
import type { ScanProps, SearchParamsProps } from "@/types";
import type { ComplianceOverviewData } from "@/types/compliance";
import {
  isKnownProviderType,
  type KnownProviderType,
  PROVIDER_DISPLAY_NAMES,
} from "@/types/providers";

import { CROSS_PROVIDER_FRAMEWORKS } from "../_lib/cross-provider-frameworks";
import type { CrossAccountFrameworkEntry } from "../_types";

import { ComplianceSectionHeader } from "./compliance-section-header";
import { CrossAccountFrameworkCard } from "./cross-account-framework-card";

/** Only provider types with at least this many accounts get cross-account
 *  cards — with a single account the view is identical to the per-scan one. */
const MIN_ACCOUNTS = 2;

/**
 * Server island for the "across accounts" section of the Cross-Provider tab:
 * for every provider type with 2+ accounts, lists the regular (per-provider)
 * frameworks that can be viewed aggregated across that type's accounts.
 *
 * The framework list per type comes from the latest completed scan of any
 * account of that type (frameworks are a property of the provider type, not
 * of the account). Universal frameworks are excluded — they already have
 * their own cross-provider cards above. Renders nothing when no provider
 * type qualifies, keeping the tab unchanged for single-account tenants.
 * Best-effort by design: a type whose scan or framework list fails to load
 * is dropped from the section rather than failing the tab.
 */
export const CrossAccountOverviewSection = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const providerTypeFilter =
    searchParams["filter[provider_type__in]"]
      ?.toString()
      .split(",")
      .filter(Boolean) ?? [];

  const [providersData, scansData] = await Promise.all([
    getAllProviders(),
    getScans({
      filters: { "filter[state]": "completed" },
      pageSize: 50,
      fields: { scans: "name,completed_at,provider" },
      include: "provider",
    }),
  ]);

  const accountCounts = new Map<KnownProviderType, number>();
  for (const provider of providersData?.data || []) {
    const type = provider.attributes.provider;
    if (!isKnownProviderType(type)) continue;
    accountCounts.set(type, (accountCounts.get(type) ?? 0) + 1);
  }

  const eligibleTypes = Array.from(accountCounts.entries())
    .filter(([type, count]) => {
      if (count < MIN_ACCOUNTS) return false;
      return (
        providerTypeFilter.length === 0 || providerTypeFilter.includes(type)
      );
    })
    .map(([type]) => type)
    .sort();

  if (eligibleTypes.length === 0) return null;

  // Latest completed scan per eligible type (the API returns scans newest
  // first). One representative scan per type is enough to enumerate the
  // type's frameworks.
  const latestScanByType = new Map<KnownProviderType, string>();
  for (const scan of (scansData?.data || []) as ScanProps[]) {
    const providerId = scan.relationships?.provider?.data?.id;
    if (!providerId) continue;
    const providerData = scansData.included?.find(
      (item: { type: string; id: string }) =>
        item.type === "providers" && item.id === providerId,
    );
    const type = providerData?.attributes?.provider;
    if (!isKnownProviderType(type)) continue;
    if (!eligibleTypes.includes(type) || latestScanByType.has(type)) continue;
    latestScanByType.set(type, scan.id);
  }

  const universalIds = new Set(
    CROSS_PROVIDER_FRAMEWORKS.map((entry) => entry.complianceId),
  );

  const entriesByType = await Promise.all(
    Array.from(latestScanByType.entries()).map(async ([type, scanId]) => {
      const compliancesData = await getCompliancesOverview({ scanId });
      const frameworks: ComplianceOverviewData[] = Array.isArray(
        compliancesData?.data,
      )
        ? compliancesData.data
        : [];

      return frameworks
        .filter(
          (compliance) =>
            compliance.attributes.framework !== "ProwlerThreatScore" &&
            !universalIds.has(compliance.id),
        )
        .map(
          (compliance): CrossAccountFrameworkEntry => ({
            complianceId: compliance.id,
            title: compliance.attributes.framework,
            version: compliance.attributes.version,
            providerType: type,
            accountCount: accountCounts.get(type) ?? 0,
          }),
        )
        .sort((a, b) => a.title.localeCompare(b.title));
    }),
  );

  const groups = entriesByType
    .filter((entries) => entries.length > 0)
    .sort((a, b) => a[0].providerType.localeCompare(b[0].providerType));
  if (groups.length === 0) return null;

  // One collapsed group per provider type instead of a flat grid: with
  // several multi-account types connected, the flat grid piles up dozens of
  // cards (each type ships 20-40 frameworks) and buries the universal
  // section's hierarchy. Collapsed-by-default keeps the catalog scannable —
  // the header carries the counts, expanding reveals that type's cards.
  const accordionItems: AccordionItemProps[] = groups.map((entries) => {
    const { providerType, accountCount } = entries[0];
    return {
      key: providerType,
      title: (
        <span className="flex items-center gap-2 text-sm font-medium">
          <ProviderTypeIcon type={providerType} size={18} />
          {PROVIDER_DISPLAY_NAMES[providerType]}
        </span>
      ),
      subtitle: `${entries.length} ${entries.length === 1 ? "framework" : "frameworks"} · ${accountCount} providers`,
      content: (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
          {entries.map((entry) => (
            <CrossAccountFrameworkCard
              key={`${entry.providerType}-${entry.complianceId}`}
              {...entry}
            />
          ))}
        </div>
      ),
      items: [],
    };
  });

  return (
    <section className="flex flex-col gap-4">
      <ComplianceSectionHeader
        title="Across providers"
        description="Single-provider frameworks aggregated across every provider of the same type, using each provider's latest completed scan. Expand a provider type to browse its frameworks."
      />
      <Accordion items={accordionItems} selectionMode="multiple" />
    </section>
  );
};
