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

const MIN_ACCOUNTS = 2;

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

  const watchlist = await loadComplianceWatchlistContext();
  const catalogIndex = buildWatchlistIndex(watchlist.entries);

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
