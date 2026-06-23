import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { getSchedules, getSchedulesPage } from "@/actions/schedules";
import { auth } from "@/auth.config";
import { PageReady } from "@/components/onboarding";
import {
  appendPendingScheduleRowsToPage,
  getProviderIdsFromScans,
  getScanJobsTab,
  getScanJobsTabFilters,
  getScanJobsUserFilters,
  mapScheduleToScanRow,
} from "@/components/scans/scans.utils";
import { ScansPageShell } from "@/components/scans/scans-page-shell";
import { ScansProvidersEmptyState } from "@/components/scans/scans-providers-empty-state";
import { SkeletonTableScans } from "@/components/scans/table";
import { ScanJobsTable } from "@/components/scans/table/scan-jobs-table";
import { ContentLayout } from "@/components/ui";
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
  type ScheduleProps,
} from "@/types/schedules";

const ACTIVE_SCAN_COUNT_PAGE_SIZE = 1;
// Pending schedule rows are derived from provider schedules, but must honor the
// same provider filters as real scan rows. Keep these filter keys typed locally
// without narrowing the global SearchParamsProps shape used by Next pages.
const PENDING_ROW_PROVIDER_FILTER = {
  PROVIDER_UID_IN: "provider_uid__in",
  PROVIDER_UID: "provider_uid",
  PROVIDER_TYPE_IN: "provider_type__in",
  PROVIDER_TYPE: "provider_type",
} as const;

type PendingRowProviderFilter =
  (typeof PENDING_ROW_PROVIDER_FILTER)[keyof typeof PENDING_ROW_PROVIDER_FILTER];
type PendingRowProviderFilterParam = `filter[${PendingRowProviderFilter}]`;

const PROVIDER_UID_FILTER_KEYS = [
  `filter[${PENDING_ROW_PROVIDER_FILTER.PROVIDER_UID_IN}]`,
  `filter[${PENDING_ROW_PROVIDER_FILTER.PROVIDER_UID}]`,
] as const satisfies ReadonlyArray<PendingRowProviderFilterParam>;

const PROVIDER_TYPE_FILTER_KEYS = [
  `filter[${PENDING_ROW_PROVIDER_FILTER.PROVIDER_TYPE_IN}]`,
  `filter[${PENDING_ROW_PROVIDER_FILTER.PROVIDER_TYPE}]`,
] as const satisfies ReadonlyArray<PendingRowProviderFilterParam>;

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
  keys: ReadonlyArray<PendingRowProviderFilterParam>,
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
  const uids = parseCsvParam(
    getFirstSearchParam(searchParams, PROVIDER_UID_FILTER_KEYS),
  );
  const types = parseCsvParam(
    getFirstSearchParam(searchParams, PROVIDER_TYPE_FILTER_KEYS),
  );

  return providers.filter(
    (provider) =>
      (uids.length === 0 || uids.includes(provider.attributes.uid)) &&
      (types.length === 0 || types.includes(provider.attributes.provider)),
  );
};

// Provider filters the `/schedules` ScheduleFilter actually exposes. The scans
// filter-bar targets providers by uid (`provider_uid__in`), which this endpoint
// does not support (it filters by provider id / type), so forwarding only these
// keys keeps pagination native AND avoids a JSON:API 400 on unknown params.
const SCHEDULE_SUPPORTED_PROVIDER_FILTERS = [
  "filter[provider]",
  "filter[provider__in]",
  "filter[provider_type]",
  "filter[provider_type__in]",
  "filter[provider_group]",
  "filter[provider_group__in]",
] as const;

/**
 * Provider filter params forwarded to `/schedules` for the schedules-only
 * Scheduled tab. The backend applies them, so pagination stays native (filtering
 * client-side would desync `meta.count`).
 */
const pickScheduleProviderFilters = (
  searchParams: SearchParamsProps,
): Record<string, string | string[]> => {
  const filters: Record<string, string | string[]> = {};
  for (const key of SCHEDULE_SUPPORTED_PROVIDER_FILTERS) {
    const value = searchParams[key];
    if (typeof value === "string" || Array.isArray(value)) {
      filters[key] = value;
    }
  }
  return filters;
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

  const providersData = await getAllProviders();
  const providers = providersData?.data ?? [];

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
      title="Scan Jobs"
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

  // The Scheduled tab is sourced purely from /schedules when the environment
  // grants advanced scheduling (Prowler Cloud). The backend filters to configured
  // schedules (filter[configured]=true), so pagination is delegated natively and
  // no /scans reconciliation is needed. Non-advanced envs keep the legacy path.
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

    const included =
      schedulesPage && "included" in schedulesPage
        ? ((schedulesPage.included ?? []) as ProviderProps[])
        : [];
    const providerById = new Map(
      included
        .filter((resource) => resource.type === "providers")
        .map((provider) => [provider.id, provider]),
    );

    const now = new Date();
    const scheduleRows = ((schedulesPage?.data ?? []) as ScheduleProps[]).map(
      (schedule) =>
        mapScheduleToScanRow(schedule, providerById.get(schedule.id), now),
    );
    const scheduleMeta =
      schedulesPage && "meta" in schedulesPage ? schedulesPage.meta : undefined;

    return (
      <ScanJobsTable
        data={scheduleRows}
        meta={scheduleMeta}
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
