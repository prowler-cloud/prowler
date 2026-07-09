import { Info } from "lucide-react";

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
  parseCrossProviderFilters,
} from "../_lib/cross-provider-frameworks";
import type { CrossProviderFrameworkSummary } from "../_types";
import { CROSS_PROVIDER_OVERVIEW_RESULT_STATUS } from "../_types";
import { CrossProviderErrorAlert } from "./cross-provider-error-alert";
import type {
  CrossProviderAccountOption,
  CrossProviderGroupOption,
} from "./cross-provider-filters";
import { CrossProviderFilters } from "./cross-provider-filters";
import { CrossProviderFrameworkCard } from "./cross-provider-framework-card";

/** Zero-state summary: the framework renders with every compatible provider
 *  chip dimmed when the API returned nothing usable (e.g. no scans yet). */
const emptySummary = (
  entry: CrossProviderFrameworkEntry,
): CrossProviderFrameworkSummary => ({
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
  const filters = parseCrossProviderFilters(searchParams);

  const [responses, providersData, providerGroupsData] = await Promise.all([
    Promise.all(
      CROSS_PROVIDER_FRAMEWORKS.map((entry) =>
        getCrossProviderComplianceOverview({
          complianceId: entry.complianceId,
          filters,
        }).then((result) => ({ entry, result })),
      ),
    ),
    getAllProviders(),
    getAllProviderGroups(),
  ]);

  const actionError = responses.find(
    ({ result }) =>
      result.status === CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR,
  );
  if (
    actionError?.result.status ===
    CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR
  ) {
    return <CrossProviderErrorAlert result={actionError.result.result} />;
  }

  const loadError = responses.find(
    ({ result }) =>
      result.status === CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR,
  );
  if (
    loadError?.result.status ===
    CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR
  ) {
    return <CrossProviderErrorAlert message={loadError.result.message} />;
  }

  const summaries: CrossProviderFrameworkSummary[] = responses.map(
    ({ entry, result }) => {
      if (result.status !== CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS) {
        return emptySummary(entry);
      }

      const data = result.response.data;
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
