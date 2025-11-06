import { Suspense } from "react";

import {
  getFindingsBySeverity,
  getFindingsByStatus,
  getThreatScore,
} from "@/actions/overview/overview";
import { getProviders } from "@/actions/providers";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types";

import { AccountsSelector } from "./components/accounts-selector";
import { ProviderTypeSelector } from "./components/provider-type-selector";
import { RiskSeverityChart } from "./components/risk-severity-chart";
import { StatusChart } from "./components/status-chart";
import { ThreatScore } from "./components/threat-score";

const FILTER_PREFIX = "filter[";

// Extract only query params that start with "filter[" for API calls
function pickFilterParams(
  params: SearchParamsProps | undefined | null,
): Record<string, string | string[] | undefined> {
  if (!params) return {};
  return Object.fromEntries(
    Object.entries(params).filter(([key]) => key.startsWith(FILTER_PREFIX)),
  );
}

export default async function NewOverviewPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const providersData = await getProviders({ page: 1, pageSize: 200 });

  return (
    <ContentLayout title="New Overview" icon="lucide:square-chart-gantt">
      <div className="xxl:grid-cols-4 mb-6 grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        <ProviderTypeSelector providers={providersData?.data ?? []} />
        <AccountsSelector providers={providersData?.data ?? []} />
      </div>
      <div className="flex flex-col gap-6 md:flex-row md:flex-wrap md:items-stretch">
        <Suspense
          fallback={
            <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
              <p className="text-zinc-400">Loading...</p>
            </div>
          }
        >
          <SSRThreatScore searchParams={resolvedSearchParams} />
        </Suspense>

        <Suspense
          fallback={
            <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
              <p className="text-zinc-400">Loading...</p>
            </div>
          }
        >
          <SSRCheckFindings searchParams={resolvedSearchParams} />
        </Suspense>

        <Suspense
          fallback={
            <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
              <p className="text-zinc-400">Loading...</p>
            </div>
          }
        >
          <SSRRiskSeverityChart searchParams={resolvedSearchParams} />
        </Suspense>
      </div>
    </ContentLayout>
  );
}

const SSRCheckFindings = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const findingsByStatus = await getFindingsByStatus({ filters });

  if (!findingsByStatus) {
    return (
      <div className="flex h-[400px] w-full max-w-md items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load findings data</p>
      </div>
    );
  }

  const {
    fail = 0,
    pass = 0,
    muted_new = 0,
    muted_changed = 0,
    fail_new = 0,
    pass_new = 0,
  } = findingsByStatus?.data?.attributes || {};

  const mutedTotal = muted_new + muted_changed;

  return (
    <StatusChart
      failFindingsData={{
        total: fail,
        new: fail_new,
        muted: mutedTotal,
      }}
      passFindingsData={{
        total: pass,
        new: pass_new,
        muted: mutedTotal,
      }}
    />
  );
};

const SSRRiskSeverityChart = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const findingsBySeverity = await getFindingsBySeverity({ filters });

  if (!findingsBySeverity) {
    return (
      <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load severity data</p>
      </div>
    );
  }

  const {
    critical = 0,
    high = 0,
    medium = 0,
    low = 0,
    informational = 0,
  } = findingsBySeverity?.data?.attributes || {};

  return (
    <RiskSeverityChart
      critical={critical}
      high={high}
      medium={medium}
      low={low}
      informational={informational}
    />
  );
};

const SSRThreatScore = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);
  const threatScoreData = await getThreatScore({ filters });

  // If no data, pass undefined score and let component handle empty state
  if (!threatScoreData?.data || threatScoreData.data.length === 0) {
    return <ThreatScore />;
  }

  // Get the first snapshot (aggregated or single provider)
  const snapshot = threatScoreData.data[0];
  const attributes = snapshot.attributes;

  // Parse score from decimal string to number and round to integer
  const score = Math.round(parseFloat(attributes.overall_score));
  const scoreDelta = attributes.score_delta
    ? Math.round(parseFloat(attributes.score_delta))
    : null;

  return (
    <ThreatScore
      score={score}
      scoreDelta={scoreDelta}
      sectionScores={attributes.section_scores}
      criticalRequirements={attributes.critical_requirements}
    />
  );
};
