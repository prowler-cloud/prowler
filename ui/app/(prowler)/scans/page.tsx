import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import {
  SCANS_PROVIDER_FILTER_FIELD,
  type ScansFilterParam,
} from "@/actions/scans/scans-filters";
import { getSchedules, getSchedulesPage } from "@/actions/schedules";
import { auth } from "@/auth.config";
import { PageReady } from "@/components/onboarding";
import {
  appendPendingScheduleRowsToPage,
  buildScheduledTabRows,
  getProviderIdsFromScans,
  getScanJobsTab,
  getScanJobsTabFilters,
  getScanJobsUserFilters,
  pickScheduleProviderFilters,
} from "@/components/scans/scans.utils";
import { ScansPageShell } from "@/components/scans/scans-page-shell";
import { ScansProvidersEmptyState } from "@/components/scans/scans-providers-empty-state";
import { SkeletonTableScans } from "@/components/scans/table";
import { ScanJobsTable } from "@/components/scans/table/scan-jobs-table";
import { ContentLayout } from "@/components/shadcn/content-layout";
import {
  buildProviderScheduleSummary,
  buildSchedulesByProviderId,
  getScanScheduleCapability,
  isScheduleConfigured,
} from "@/lib/schedules";
import { isCloud } from "@/lib/shared/env";
import {
  ProviderProps,
  SCAN_JOBS_TAB,
  SCAN_TRIGGER,
  ScanProps,
  SearchParamsProps,
} from "@/types";
import {
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
} from "@/types/schedules";

const ACTIVE_SCAN_COUNT_PAGE_SIZE = 1;
// Pending schedule rows are derived from provider schedules, but must honor the
// same provider filters as real scan rows. The filter keys live with the scans
// action (SCANS_PROVIDER_FILTER_FIELD) so they stay in sync with ScansFilterParam.
const PROVIDER_ID_FILTER_KEYS = [
  `filter[${SCANS_PROVIDER_FILTER_FIELD.PROVIDER_IN}]`,
  `filter[${SCANS_PROVIDER_FILTER_FIELD.PROVIDER}]`,
] as const satisfies ReadonlyArray<ScansFilterParam>;

const PROVIDER_TYPE_FILTER_KEYS = [
  `filter[${SCANS_PROVIDER_FILTER_FIELD.PROVIDER_TYPE_IN}]`,
  `filter[${SCANS_PROVIDER_FILTER_FIELD.PROVIDER_TYPE}]`,
] as const satisfies ReadonlyArray<ScansFilterParam>;

const PROVIDER_GROUP_FILTER_KEYS = [
  `filter[${SCANS_PROVIDER_FILTER_FIELD.PROVIDER_GROUPS_IN}]`,
] as const satisfies ReadonlyArray<ScansFilterParam>;

const getFilterSearchQuery = (
  filters: Record<string, string | string[]>,
): string => {
  const value = filters["filter[search]"];
  if (Array.isArray(value)) return value[0] ?? "";

  return value ?? "";
};

const parseCsvParam = (value?: string | string[]): string[] => {
  const rawValue = Array.isArray(value) ? value.join(",") : value;
  if (!rawValue) return [];

  return rawValue
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
};

const getFirstSearchParam = (
  searchParams: SearchParamsProps,
  keys: ReadonlyArray<ScansFilterParam>,
): string | string[] | undefined => {
  for (const key of keys) {
    const value = searchParams[key];
    if (value !== undefined) return value;
  }

  return undefined;
};

/** Applies the table's provider filters to synthetic pending-schedule rows. */
const filterProvidersForPendingRows = (
  providers: ProviderProps[],
  searchParams: SearchParamsProps,
): ProviderProps[] => {
  const ids = parseCsvParam(
    getFirstSearchParam(searchParams, PROVIDER_ID_FILTER_KEYS),
  );
  const types = parseCsvParam(
    getFirstSearchParam(searchParams, PROVIDER_TYPE_FILTER_KEYS),
  );
  const groups = parseCsvParam(
    getFirstSearchParam(searchParams, PROVIDER_GROUP_FILTER_KEYS),
  );

  return providers.filter(
    (provider) =>
      (ids.length === 0 || ids.includes(provider.id)) &&
      (types.length === 0 || types.includes(provider.attributes.provider)) &&
      (groups.length === 0 ||
        (provider.relationships?.provider_groups?.data ?? []).some((group) =>
          groups.includes(group.id),
        )),
  );
};

const getActiveScanCount = async (
  searchParams: SearchParamsProps,
): Promise<number> => {
  const userFilters = getScanJobsUserFilters(searchParams);
  const filters = {
    ...userFilters,
    ...getScanJobsTabFilters(SCAN_JOBS_TAB.ACTIVE),
  };

  const scansData = await getScans({
    query: getFilterSearchQuery(filters),
    page: 1,
    pageSize: ACTIVE_SCAN_COUNT_PAGE_SIZE,
    filters,
    fields: { scans: "state" },
  });

  return scansData && "meta" in scansData ? scansData.meta.pagination.count : 0;
};

/**
 * A provider can already have a real scheduled scan on a different page.
 * Current-page rows are not enough to decide whether a schedule needs a
 * synthetic Pending row, so fetch all scheduled scan provider ids when the
 * backend paginated result is larger than the current slice.
 */
const getCoveredScheduledProviderIds = async ({
  currentScans,
  realScanCount,
  query,
  filters,
}: {
  currentScans: ScanProps[];
  realScanCount: number;
  query: string;
  filters: Record<string, string | string[]>;
}): Promise<Set<string>> => {
  if (realScanCount === 0 || currentScans.length === realScanCount) {
    return getProviderIdsFromScans(currentScans);
  }

  const allScheduledScansData = await getScans({
    query,
    page: 1,
    pageSize: realScanCount,
    filters,
    include: "provider",
  });

  return getProviderIdsFromScans(
    (allScheduledScansData?.data ?? []) as ScanProps[],
  );
};

export default async function Scans({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const session = await auth();
  const resolvedSearchParams = await searchParams;

  const [providersData, providerGroupsData] = await Promise.all([
    getAllProviders(),
    getAllProviderGroups(),
  ]);
  const providers = providersData?.data ?? [];
  const providerGroups = providerGroupsData?.data ?? [];

  const connectedProviders = providers.filter(
    (provider: ProviderProps) =>
      provider.attributes.connection.connected === true,
  );
  const thereIsNoProviders = providers.length === 0;
  const thereIsNoProvidersConnected =
    !thereIsNoProviders && connectedProviders.length === 0;
  const missingScanPrerequisite =
    thereIsNoProviders || thereIsNoProvidersConnected;

  if (
    missingScanPrerequisite &&
    resolvedSearchParams.onboarding === "view-first-scan"
  ) {
    redirect("/providers?onboarding=add-provider");
  }

  const hasManageScansPermission = Boolean(
    session?.user?.permissions?.manage_scans,
  );
  const activeScanCount = missingScanPrerequisite
    ? 0
    : await getActiveScanCount(resolvedSearchParams);
  const onboardingAction = missingScanPrerequisite
    ? {
        flowId: "view-first-scan",
        fallbackFlowId: "add-provider",
        useFallback: true,
      }
    : { flowId: "view-first-scan" };

  return (
    <ContentLayout
      title="Scans"
      icon="lucide:timer"
      onboardingAction={onboardingAction}
    >
      {missingScanPrerequisite ? (
        <>
          {/* The populated branch mounts <PageReady/> inside ScansPageShell to
              enable the navbar tour icon. The empty branch must mark the route
              ready too, otherwise the icon (which falls back to the add-provider
              flow here) stays hidden for users with no connected provider. */}
          <PageReady />
          <ScansProvidersEmptyState thereIsNoProviders={thereIsNoProviders} />
        </>
      ) : (
        <ScansPageShell
          providers={providers}
          providerGroups={providerGroups}
          hasManageScansPermission={hasManageScansPermission}
          activeScanCount={activeScanCount}
        >
          <Suspense
            fallback={
              <SkeletonTableScans
                tab={getScanJobsTab(resolvedSearchParams.tab)}
              />
            }
          >
            <SSRDataTableScans
              searchParams={resolvedSearchParams}
              providers={providers}
            />
          </Suspense>
        </ScansPageShell>
      )}
    </ContentLayout>
  );
}

const SSRDataTableScans = async ({
  searchParams,
  providers,
  scanScheduleCapability,
}: {
  searchParams: SearchParamsProps;
  providers: ProviderProps[];
  scanScheduleCapability?: ScanScheduleCapability;
}) => {
  const tab = getScanJobsTab(searchParams.tab);

  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
  const sort = searchParams.sort?.toString();

  const userFilters = Object.entries(searchParams).filter(([key]) =>
    key.startsWith("filter["),
  );
  const hasUserFilters = userFilters.length > 0;

  const filters = {
    ...getScanJobsUserFilters(searchParams),
    ...getScanJobsTabFilters(
      tab,
      searchParams["filter[state__in]"] ?? searchParams["filter[state]"],
    ),
  };

  const query = (filters["filter[search]"] as string) || "";

  // Advanced (Cloud) sources the Scheduled tab from /schedules; other envs keep the legacy /scans path.
  const capability =
    scanScheduleCapability ?? getScanScheduleCapability(isCloud());

  if (
    tab === SCAN_JOBS_TAB.SCHEDULED &&
    capability === SCAN_SCHEDULE_CAPABILITY.ADVANCED
  ) {
    const schedulesPage = await getSchedulesPage({
      page,
      pageSize,
      sort,
      filters: pickScheduleProviderFilters(searchParams),
    });
    const { data, meta } = buildScheduledTabRows(schedulesPage, new Date());

    return (
      <ScanJobsTable
        data={data}
        meta={meta}
        tab={tab}
        hasFilters={hasUserFilters}
        scanScheduleCapability={capability}
      />
    );
  }

  const scansData = await getScans({
    query,
    page,
    sort,
    filters,
    pageSize,
    include: "provider",
  });

  const scans = scansData?.data;
  const included = scansData?.included;
  const meta = scansData && "meta" in scansData ? scansData.meta : undefined;

  const expandedScansData: ScanProps[] =
    scans?.map((scan: ScanProps) => {
      const providerId = scan.relationships?.provider?.data?.id;

      const providerData = included?.find(
        (item: { type: string; id: string }) =>
          item.type === "providers" && item.id === providerId,
      );

      if (!providerData) return scan;

      return {
        ...scan,
        providerInfo: {
          provider: providerData.attributes.provider,
          uid: providerData.attributes.uid,
          alias: providerData.attributes.alias,
        },
      };
    }) || [];

  const needsSchedules =
    tab === SCAN_JOBS_TAB.SCHEDULED ||
    expandedScansData.some(
      (scan) => scan.attributes.trigger === SCAN_TRIGGER.SCHEDULED,
    );
  const schedulesResult = needsSchedules ? await getSchedules() : null;

  // Schedules are keyed by provider id so real scheduled scan rows can display
  // cadence/next-run info, and schedule-only providers can become Pending rows.
  const schedulesByProviderId = buildSchedulesByProviderId(schedulesResult);

  const scansWithSchedule = expandedScansData.map((scan) => {
    if (scan.attributes.trigger !== SCAN_TRIGGER.SCHEDULED) return scan;

    const providerId = scan.relationships?.provider?.data?.id;
    const schedule = providerId ? schedulesByProviderId[providerId] : undefined;
    if (!schedule || !isScheduleConfigured(schedule)) return scan;

    return {
      ...scan,
      providerSchedule: buildProviderScheduleSummary(schedule, new Date()),
    };
  });

  let tableData = scansWithSchedule;
  let tableMeta = meta;
  if (tab === SCAN_JOBS_TAB.SCHEDULED) {
    // The backend paginates real scans only. Pending schedule rows are generated
    // client-side, so reconcile both sources before passing data/meta to the table.
    const coveredProviderIds = await getCoveredScheduledProviderIds({
      currentScans: scansWithSchedule,
      realScanCount: meta?.pagination?.count ?? scansWithSchedule.length,
      query,
      filters,
    });
    const scheduledTable = appendPendingScheduleRowsToPage({
      scans: scansWithSchedule,
      meta,
      page,
      pageSize,
      providers: filterProvidersForPendingRows(providers, searchParams),
      schedulesByProviderId,
      coveredProviderIds,
      now: new Date(),
    });

    tableData = scheduledTable.data;
    tableMeta = scheduledTable.meta;
  }

  return (
    <ScanJobsTable
      data={tableData}
      meta={tableMeta}
      tab={tab}
      hasFilters={hasUserFilters}
      scanScheduleCapability={scanScheduleCapability}
    />
  );
};
