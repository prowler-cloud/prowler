import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { auth } from "@/auth.config";
import { PageReady } from "@/components/onboarding";
import {
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
  ProviderProps,
  SCAN_JOBS_TAB,
  ScanProps,
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
            <SSRDataTableScans searchParams={resolvedSearchParams} />
          </Suspense>
        </ScansPageShell>
      )}
    </ContentLayout>
  );
}

const SSRDataTableScans = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
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

  const expandedScansData =
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

  return (
    <ScanJobsTable
      data={expandedScansData}
      meta={meta}
      tab={tab}
      hasFilters={hasUserFilters}
    />
  );
};
