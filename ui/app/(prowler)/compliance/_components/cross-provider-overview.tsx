import { AlertTriangle, Info } from "lucide-react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { buildComplianceContext } from "@/lib/lighthouse/context/contributions";
import { SearchParamsProps } from "@/types";
import type { KnownProviderType } from "@/types/providers";

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

  // Action errors (402 usage limit, 403) gate the whole feature, not one
  // framework, so any of them replaces the tab instead of degrading it.
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

  // Load errors are per-framework and often transient: degrade to a partial
  // view with a warning, and only replace the tab when nothing loaded.
  const loadErrors = responses.flatMap(({ entry, result }) =>
    result.status === CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR
      ? [{ entry, result }]
      : [],
  );
  if (loadErrors.length === responses.length && loadErrors.length > 0) {
    return <CrossProviderErrorAlert message={loadErrors[0].result.message} />;
  }

  const summaries: CrossProviderFrameworkSummary[] = responses
    .filter(
      ({ result }) =>
        result.status !== CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR,
    )
    .map(({ entry, result }) => {
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
    });

  const compatibleTypes = Array.from(
    new Set<KnownProviderType>(
      CROSS_PROVIDER_FRAMEWORKS.flatMap((entry) => entry.compatibleProviders),
    ),
  ).sort();

  const providerAccounts: CrossProviderAccountOption[] = (
    providersData?.data || []
  )
    .filter((provider) =>
      compatibleTypes.some((type) => type === provider.attributes.provider),
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
      {summaries.slice(0, 7).map((summary) => (
        <LighthouseContextContributor
          key={`cross-provider-${summary.complianceId}-${summary.requirementsPassed}-${summary.requirementsFailed}`}
          contributorId={`cross-provider-${summary.complianceId}`}
          item={buildComplianceContext({
            pathname: "/compliance",
            id: summary.complianceId,
            framework: summary.title,
            version: summary.version,
            mode: "cross-provider",
            passed: summary.requirementsPassed,
            failed: summary.requirementsFailed,
            total: summary.totalRequirements,
          })}
        />
      ))}
      <CrossProviderFilters
        providerTypes={compatibleTypes}
        providerAccounts={providerAccounts}
        providerGroups={providerGroups}
      />

      {loadErrors.length > 0 && (
        <Alert variant="warning">
          <AlertTriangle className="size-4" />
          <AlertDescription>
            Could not load{" "}
            {loadErrors.map(({ entry }) => entry.title).join(", ")}. Showing the
            frameworks that loaded — try again later.
          </AlertDescription>
        </Alert>
      )}

      {loadErrors.length === 0 &&
        summaries.every((summary) => summary.totalRequirements === 0) && (
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
