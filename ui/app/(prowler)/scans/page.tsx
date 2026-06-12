import { Suspense } from "react";

import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { getSchedules } from "@/actions/schedules";
import { auth } from "@/auth.config";
import {
  buildPendingScheduleRows,
  getScanJobsTab,
  getScanJobsTabFilters,
  getScanJobsUserFilters,
} from "@/components/scans/scans.utils";
import { ScansPageShell } from "@/components/scans/scans-page-shell";
import { ScansProvidersEmptyState } from "@/components/scans/scans-providers-empty-state";
import { SkeletonTableScans } from "@/components/scans/table";
import { ScanJobsTable } from "@/components/scans/table/scan-jobs-table";
import { ContentLayout } from "@/components/ui";
import {
  describeScheduleCadence,
  getNextScheduledRunInTimezone,
  getScheduleCadenceParts,
  isScheduleConfigured,
} from "@/lib/schedules";
import {
  ProviderProps,
  SCAN_JOBS_TAB,
  SCAN_TRIGGER,
  ScanProps,
  ScheduleAttributes,
  ScheduleProps,
  SearchParamsProps,
} from "@/types";

const ACTIVE_SCAN_COUNT_PAGE_SIZE = 1;

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

/** Applies the table's provider filters to synthetic pending-schedule rows. */
const filterProvidersForPendingRows = (
  providers: ProviderProps[],
  searchParams: SearchParamsProps,
): ProviderProps[] => {
  const uids = parseCsvParam(
    searchParams["filter[provider_uid__in]"] ??
      searchParams["filter[provider_uid]"],
  );
  const types = parseCsvParam(
    searchParams["filter[provider_type__in]"] ??
      searchParams["filter[provider_type]"],
  );

  return providers.filter(
    (provider) =>
      (uids.length === 0 || uids.includes(provider.attributes.uid)) &&
      (types.length === 0 || types.includes(provider.attributes.provider)),
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

  const hasManageScansPermission = Boolean(
    session?.user?.permissions?.manage_scans,
  );
  const activeScanCount =
    thereIsNoProviders || thereIsNoProvidersConnected
      ? 0
      : await getActiveScanCount(resolvedSearchParams);

  return (
    <ContentLayout title="Scan Jobs" icon="lucide:timer">
      {thereIsNoProviders || thereIsNoProvidersConnected ? (
        <ScansProvidersEmptyState thereIsNoProviders={thereIsNoProviders} />
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
}: {
  searchParams: SearchParamsProps;
  providers: ProviderProps[];
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

  const schedulesByProviderId: Record<string, ScheduleAttributes> = {};
  if (schedulesResult && !schedulesResult.error) {
    for (const schedule of (schedulesResult.data ?? []) as ScheduleProps[]) {
      schedulesByProviderId[schedule.id] = schedule.attributes;
    }
  }

  const scansWithSchedule = expandedScansData.map((scan) => {
    if (scan.attributes.trigger !== SCAN_TRIGGER.SCHEDULED) return scan;

    const providerId = scan.relationships?.provider?.data?.id;
    const schedule = providerId ? schedulesByProviderId[providerId] : undefined;
    if (!schedule || !isScheduleConfigured(schedule)) return scan;

    // Absent field (older API) -> client estimate; explicit null (paused) -> no time.
    const nextScanAt =
      schedule.next_scan_at === undefined && schedule.scan_enabled
        ? (getNextScheduledRunInTimezone(schedule, new Date())?.toISOString() ??
          null)
        : (schedule.next_scan_at ?? null);

    return {
      ...scan,
      providerSchedule: {
        summary: describeScheduleCadence(schedule),
        cadence: getScheduleCadenceParts(schedule).cadence,
        nextScanAt,
        lastScanAt: schedule.last_scan_at ?? null,
      },
    };
  });

  let tableData = scansWithSchedule;
  if (tab === SCAN_JOBS_TAB.SCHEDULED) {
    // Append pending rows only after the last page of real rows.
    const totalPages = meta?.pagination?.pages ?? 0;
    if (page >= totalPages) {
      const coveredProviderIds = new Set(
        scansWithSchedule
          .map((scan) => scan.relationships?.provider?.data?.id)
          .filter((id): id is string => Boolean(id)),
      );

      tableData = [
        ...scansWithSchedule,
        ...buildPendingScheduleRows({
          providers: filterProvidersForPendingRows(providers, searchParams),
          schedulesByProviderId,
          coveredProviderIds,
          now: new Date(),
        }),
      ];
    }
  }

  return (
    <ScanJobsTable
      data={tableData}
      meta={meta}
      tab={tab}
      hasFilters={hasUserFilters}
    />
  );
};
