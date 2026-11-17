import { Suspense } from "react";

import {
  getRealtimeFrameworks,
  getRealtimePolicy,
} from "@/app/(prowler)/realtime/_actions";
import {
  CostTab,
  CostTabSkeleton,
} from "@/app/(prowler)/realtime/_components/cost/cost-tab";
import {
  DetectionsTab,
  DetectionsTabSkeleton,
} from "@/app/(prowler)/realtime/_components/detections/detections-tab";
import {
  FindingsTab,
  FindingsTabSkeleton,
} from "@/app/(prowler)/realtime/_components/findings/findings-tab";
import {
  OverviewTab,
  OverviewTabSkeleton,
} from "@/app/(prowler)/realtime/_components/overview/overview-tab";
import {
  RemediationTab,
  RemediationTabSkeleton,
} from "@/app/(prowler)/realtime/_components/remediation/remediation-tab";
import { RealtimeAutoRefresh } from "@/app/(prowler)/realtime/_components/shared/realtime-auto-refresh";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import {
  StreamTab,
  StreamTabSkeleton,
} from "@/app/(prowler)/realtime/_components/stream/stream-tab";
import { getOverview } from "@/app/(prowler)/realtime/_lib/cached";
import { isRealtimeDemo } from "@/app/(prowler)/realtime/_lib/demo";
import { frameworkLabel } from "@/app/(prowler)/realtime/_lib/display";
import {
  canManageRealtime,
  loadAwsProviders,
} from "@/app/(prowler)/realtime/_lib/load";
import { resolveProviderId } from "@/app/(prowler)/realtime/_lib/providers";
import {
  firstParam,
  parseTab,
  REALTIME_PARAM,
  REALTIME_TAB,
  type RealtimeSearchParams,
  type RealtimeTab,
} from "@/app/(prowler)/realtime/_lib/routes";
import type { RealtimeTabProps } from "@/app/(prowler)/realtime/_types/view";

import { RealtimeAccountHeader } from "./realtime-account-header";
import { RealtimeDemoBanner } from "./realtime-demo-banner";
import { RealtimeNoAccount } from "./realtime-no-account";
import { RealtimeTabsNav } from "./realtime-tabs-nav";

/** How often each tab re-reads its data while visible. */
const REFRESH_MS: Record<RealtimeTab, number> = {
  [REALTIME_TAB.OVERVIEW]: 30_000,
  [REALTIME_TAB.DETECTIONS]: 15_000,
  [REALTIME_TAB.REMEDIATION]: 15_000,
  [REALTIME_TAB.STREAM]: 10_000,
  [REALTIME_TAB.FINDINGS]: 60_000,
  [REALTIME_TAB.COST]: 60_000,
};

const TAB_CONTENT = {
  [REALTIME_TAB.OVERVIEW]: { Tab: OverviewTab, Skeleton: OverviewTabSkeleton },
  [REALTIME_TAB.DETECTIONS]: {
    Tab: DetectionsTab,
    Skeleton: DetectionsTabSkeleton,
  },
  [REALTIME_TAB.REMEDIATION]: {
    Tab: RemediationTab,
    Skeleton: RemediationTabSkeleton,
  },
  [REALTIME_TAB.STREAM]: { Tab: StreamTab, Skeleton: StreamTabSkeleton },
  [REALTIME_TAB.FINDINGS]: { Tab: FindingsTab, Skeleton: FindingsTabSkeleton },
  [REALTIME_TAB.COST]: { Tab: CostTab, Skeleton: CostTabSkeleton },
} satisfies Record<
  RealtimeTab,
  {
    Tab: (props: RealtimeTabProps) => Promise<React.ReactNode>;
    Skeleton: () => React.ReactNode;
  }
>;

/** Params that open a side panel do not reload the table behind it. */
const PANEL_PARAMS: readonly string[] = [
  REALTIME_PARAM.DETECTION,
  REALTIME_PARAM.ACTION,
  REALTIME_PARAM.ANOMALY,
];

const dataKey = (params: RealtimeSearchParams): string =>
  JSON.stringify(
    Object.entries(params)
      .filter(([key]) => !PANEL_PARAMS.includes(key))
      .sort(([a], [b]) => a.localeCompare(b)),
  );

interface RealtimeDashboardProps {
  searchParams: RealtimeSearchParams;
}

export async function RealtimeDashboard({
  searchParams,
}: RealtimeDashboardProps) {
  const providersResult = await loadAwsProviders();
  if (!providersResult.ok)
    return <RealtimePanelError failure={providersResult} />;
  const { providers } = providersResult;
  if (providers.length === 0) return <RealtimeNoAccount />;

  const providerId = resolveProviderId(
    providers,
    firstParam(searchParams, REALTIME_PARAM.PROVIDER),
  ) as string;
  const tab = parseTab(firstParam(searchParams, REALTIME_PARAM.TAB));

  const [policyResult, canManage] = await Promise.all([
    getRealtimePolicy(providerId),
    canManageRealtime(),
  ]);
  if (!policyResult.ok) return <RealtimePanelError failure={policyResult} />;

  const policy = policyResult.data;
  const demo = isRealtimeDemo(policy);
  const [overviewResult, frameworksResult] = await Promise.all([
    getOverview(providerId, demo),
    policy?.frameworks.length ? getRealtimeFrameworks() : Promise.resolve(null),
  ]);
  const overview = overviewResult.ok ? overviewResult.data : null;
  const frameworkNames = (policy?.frameworks ?? []).map((id) =>
    frameworkLabel(id, frameworksResult?.ok ? frameworksResult.data : []),
  );

  const { Tab, Skeleton } = TAB_CONTENT[tab];
  const tabProps: RealtimeTabProps = {
    providerId,
    demo,
    canManage,
    searchParams,
  };

  return (
    <div className="flex flex-col gap-6">
      {demo && <RealtimeDemoBanner providerId={providerId} />}
      <RealtimeAccountHeader
        providers={providers}
        providerId={providerId}
        tab={tab}
        policy={policy}
        overview={overview}
        frameworkNames={frameworkNames}
        canManage={canManage}
        demo={demo}
      />
      {!overviewResult.ok && <RealtimePanelError failure={overviewResult} />}
      <RealtimeTabsNav
        providerId={providerId}
        activeTab={tab}
        overview={overview}
      />
      <Suspense key={dataKey(searchParams)} fallback={<Skeleton />}>
        <Tab {...tabProps} />
      </Suspense>
      {!demo && (
        <RealtimeAutoRefresh
          key={`${providerId}:${tab}`}
          intervalMs={REFRESH_MS[tab]}
        />
      )}
    </div>
  );
}
