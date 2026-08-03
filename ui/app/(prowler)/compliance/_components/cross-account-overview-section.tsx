import { getCompliancesOverview } from "@/actions/compliances";
import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import {
  Section,
  SectionContent,
  SectionDescription,
  SectionHeader,
  SectionTitle,
} from "@/components/shadcn/section/section";
import {
  buildWatchlistIndex,
  resolveCatalogEntry,
} from "@/lib/compliance/watchlist";
import type { SearchParamsProps } from "@/types";
import type { ComplianceOverviewData } from "@/types/compliance";
import { isKnownProviderType, type KnownProviderType } from "@/types/providers";

import { CROSS_PROVIDER_FRAMEWORKS } from "../_lib/cross-provider-frameworks";
import { loadComplianceWatchlistContext } from "../_lib/watchlist-context";
import type { CrossAccountFrameworkEntry } from "../_types";

import type { CrossAccountGroup } from "./cross-account-framework-list";
import { CrossAccountFrameworkList } from "./cross-account-framework-list";

/** Only provider types with at least this many accounts get cross-account
 *  cards — with a single account the view is identical to the per-scan one. */
const MIN_ACCOUNTS = 2;

/**
 * Server island for the "across accounts" section of the Cross-Provider tab:
 * for every provider type with 2+ accounts, lists the regular (per-provider)
 * frameworks that can be viewed aggregated across that type's accounts.
 *
 * The framework list per type comes from a completed scan of any account of
 * that type (frameworks are a property of the provider type, not of the
 * account). Universal frameworks are excluded — they already have
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
  const providerFilters = {
    "filter[provider_type__in]":
      searchParams["filter[provider_type__in]"]?.toString(),
    "filter[id__in]": searchParams["filter[provider_id__in]"]?.toString(),
    "filter[provider_groups__in]":
      searchParams["filter[provider_groups__in]"]?.toString(),
  };
  const providerTypeFilter =
    providerFilters["filter[provider_type__in]"]?.split(",").filter(Boolean) ??
    [];
  const providersData = await getAllProviders({ filters: providerFilters });

  const accountCounts = new Map<KnownProviderType, number>();
  const providerIdsByType = new Map<KnownProviderType, string[]>();
  for (const provider of providersData?.data || []) {
    const type = provider.attributes.provider;
    if (!isKnownProviderType(type)) continue;
    accountCounts.set(type, (accountCounts.get(type) ?? 0) + 1);
    providerIdsByType.set(type, [
      ...(providerIdsByType.get(type) ?? []),
      provider.id,
    ]);
  }

  const eligibleTypes = Array.from(accountCounts.entries())
    .filter(
      ([type, count]) =>
        count >= MIN_ACCOUNTS &&
        (providerTypeFilter.length === 0 || providerTypeFilter.includes(type)),
    )
    .map(([type]) => type)
    .sort();

  if (eligibleTypes.length === 0) return null;

  // Resolve one representative scan independently for every eligible type.
  // A single global scans page can omit less-recent provider types on tenants
  // with a large scan history.
  const scansByType = await Promise.all(
    eligibleTypes.map(async (type) => {
      const scansData = await getScans({
        filters: {
          "filter[state]": "completed",
          "filter[provider_type]": type,
          "filter[provider__in]": (providerIdsByType.get(type) ?? []).join(","),
        },
        pageSize: 1,
        fields: { scans: "name" },
      });
      const scanId = scansData?.data?.[0]?.id;
      return scanId ? ([type, scanId] as const) : null;
    }),
  );
  const representativeScanByType = new Map(
    scansByType.filter((entry) => entry !== null),
  );

  const universalIds = new Set(
    CROSS_PROVIDER_FRAMEWORKS.map((entry) => entry.complianceId),
  );

  const entriesByType = await Promise.all(
    Array.from(representativeScanByType.entries()).map(
      async ([type, scanId]) => {
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
      },
    ),
  );

  const groups = entriesByType
    .filter((entries) => entries.length > 0)
    .sort((a, b) => a[0].providerType.localeCompare(b[0].providerType));
  if (groups.length === 0) return null;

  // The cross-account endpoints have no `filter[in_watchlist]` either, so
  // pinned state comes from joining the catalog on the same key. Deliberately
  // un-narrowed: the join keys on `(compliance_id, provider_type)`, so the full
  // catalog resolves these cards exactly like a narrowed one — and the full one
  // is already loaded for the tab bar and the cross-provider grid, which makes
  // this a deduplicated call rather than a second paginated fetch.
  const watchlist = await loadComplianceWatchlistContext();
  const catalogIndex = buildWatchlistIndex(watchlist.entries);

  // Pinned state is resolved here rather than in the client shell: the join
  // against the catalog is server data, and the shell only decides what the
  // stored filter lets through. One lookup per framework — the pinned flag and
  // the entry id come off the same catalog row.
  const listGroups: CrossAccountGroup[] = groups.map((entries) => ({
    providerType: entries[0].providerType,
    accountCount: entries[0].accountCount,
    entries: entries.map((entry) => {
      const catalogEntry = resolveCatalogEntry(catalogIndex, {
        complianceId: entry.complianceId,
        providerType: entry.providerType,
      });

      return {
        ...entry,
        pinned: catalogEntry?.inWatchlist === true,
        watchlistEntryId: catalogEntry?.watchlistEntryId ?? null,
      };
    }),
  }));

  return (
    <Section>
      <SectionHeader>
        <SectionTitle>Across providers</SectionTitle>
        <SectionDescription>
          Single-provider frameworks aggregated across every provider of the
          same type, using each provider&apos;s latest completed scan. Expand a
          provider type to browse its frameworks.
        </SectionDescription>
      </SectionHeader>
      <SectionContent>
        <CrossAccountFrameworkList
          groups={listGroups}
          canManageWatchlist={watchlist.canManage}
          watchlistEnabled={watchlist.entries.length > 0}
        />
      </SectionContent>
    </Section>
  );
};
