import { Info } from "lucide-react";
import { redirect } from "next/navigation";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { SearchParamsProps } from "@/types";
import type { ProviderType } from "@/types/providers";

import { getCrossProviderComplianceOverview } from "../_actions/cross-provider";
import { computeProviderBreakdown } from "../_lib/cross-provider-adapter";
import {
  CROSS_PROVIDER_FRAMEWORKS,
  type CrossProviderFrameworkEntry,
} from "../_lib/cross-provider-frameworks";
import type {
  CrossProviderOverviewData,
  ProviderBreakdownEntry,
} from "../_types";
import type {
  CrossProviderAccountOption,
  CrossProviderGroupOption,
} from "./cross-provider-filters";
import { CrossProviderFilters } from "./cross-provider-filters";
import { CrossProviderFrameworkCard } from "./cross-provider-framework-card";

interface FrameworkCardSummary {
  complianceId: string;
  title: string;
  version: string;
  description: string;
  requirementsPassed: number;
  requirementsFailed: number;
  requirementsManual: number;
  totalRequirements: number;
  providerBreakdown: ProviderBreakdownEntry[];
}

/** Zero-state summary: the framework renders with every compatible provider
 *  chip dimmed when the API returned nothing usable (e.g. no scans yet). */
const emptySummary = (
  entry: CrossProviderFrameworkEntry,
): FrameworkCardSummary => ({
  complianceId: entry.complianceId,
  title: entry.title,
  version: entry.version,
  description: entry.description,
  requirementsPassed: 0,
  requirementsFailed: 0,
  requirementsManual: 0,
  totalRequirements: 0,
  providerBreakdown: entry.compatibleProviders.map((provider) => ({
    provider,
    pass: 0,
    fail: 0,
    manual: 0,
    total: 0,
    score: 0,
    unscanned: true,
  })),
});

/**
 * Server island for the Cross-Provider tab: fetches the roll-up for every
 * catalog framework in parallel and renders the filter row plus the cards
 * grid. Rendered only in Prowler Cloud with the tab active, so OSS and the
 * Per Scan tab never pay for these aggregation calls.
 */
export const CrossProviderOverview = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const filters = {
    providerTypes:
      searchParams["filter[provider_type__in]"]?.toString() || undefined,
    providerIds:
      searchParams["filter[provider_id__in]"]?.toString() || undefined,
    providerGroups:
      searchParams["filter[provider_groups__in]"]?.toString() || undefined,
    regions: searchParams["filter[region__in]"]?.toString() || undefined,
  };

  const [responses, providersData, providerGroupsData] = await Promise.all([
    Promise.all(
      CROSS_PROVIDER_FRAMEWORKS.map((entry) =>
        getCrossProviderComplianceOverview({
          complianceId: entry.complianceId,
          filters,
        }).then((response) => ({ entry, response })),
      ),
    ),
    getAllProviders(),
    getAllProviderGroups(),
  ]);

  // Cross-provider is subscription-gated tenant-wide: any 402 means every
  // framework is gated, so forward the billing signal instead of rendering
  // empty cards that would swallow it.
  const billingRedirect = responses.find(
    ({ response }) =>
      response &&
      typeof response === "object" &&
      "redirectTo" in response &&
      response.redirectTo,
  );
  if (billingRedirect) {
    redirect((billingRedirect.response as { redirectTo: string }).redirectTo);
  }

  const summaries: FrameworkCardSummary[] = responses.map(
    ({ entry, response }) => {
      const data = (response as { data?: CrossProviderOverviewData } | null)
        ?.data;
      if (!data?.attributes) return emptySummary(entry);

      const attrs = data.attributes;
      return {
        complianceId: entry.complianceId,
        title: entry.title,
        version: entry.version,
        description: entry.description,
        requirementsPassed: attrs.requirements_passed,
        requirementsFailed: attrs.requirements_failed,
        requirementsManual: attrs.requirements_manual,
        totalRequirements: attrs.total_requirements,
        providerBreakdown: computeProviderBreakdown(attrs),
      };
    },
  );

  const compatibleTypes = Array.from(
    new Set<ProviderType>(
      CROSS_PROVIDER_FRAMEWORKS.flatMap((entry) => entry.compatibleProviders),
    ),
  ).sort();

  const providerAccounts: CrossProviderAccountOption[] = (
    providersData?.data || []
  )
    .filter((provider) =>
      compatibleTypes.includes(provider.attributes.provider),
    )
    .map((provider) => ({
      id: provider.id,
      label: provider.attributes.alias
        ? `${provider.attributes.alias} (${provider.attributes.uid})`
        : provider.attributes.uid,
      type: provider.attributes.provider,
    }));

  const providerGroups: CrossProviderGroupOption[] = (
    providerGroupsData?.data || []
  ).map((group) => ({ id: group.id, name: group.attributes.name }));

  return (
    <div className="flex flex-col gap-6">
      <CrossProviderFilters
        providerTypes={compatibleTypes}
        providerAccounts={providerAccounts}
        providerGroups={providerGroups}
        // The API has no cross-provider region catalog endpoint yet; the
        // filter is hidden until options exist (URL param still honored).
        regions={[]}
      />

      {summaries.every((summary) => summary.totalRequirements === 0) && (
        <Alert variant="info">
          <Info className="size-4" />
          <AlertDescription>
            No cross-provider compliance data yet. Universal frameworks
            aggregate the latest completed scan of every compatible provider —
            run a scan to populate these cards.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
        {summaries.map((summary) => (
          <CrossProviderFrameworkCard key={summary.complianceId} {...summary} />
        ))}
      </div>
    </div>
  );
};
