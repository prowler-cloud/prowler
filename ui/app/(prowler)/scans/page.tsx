import { Suspense } from "react";

import { getAllProviders } from "@/actions/providers";
import { getScans, getScansByState } from "@/actions/scans";
import { auth } from "@/auth.config";
import { MutedFindingsConfigButton } from "@/components/providers";
import {
  AutoRefresh,
  NoProvidersAdded,
  NoProvidersConnected,
  ScansFilters,
} from "@/components/scans";
import { LaunchScanWorkflow } from "@/components/scans/launch-workflow";
import { SkeletonTableScans } from "@/components/scans/table";
import { ColumnGetScans } from "@/components/scans/table/scans";
import { ContentLayout } from "@/components/ui";
import { CustomBanner } from "@/components/ui/custom/custom-banner";
import { DataTable } from "@/components/ui/table";
import {
  createProviderDetailsMapping,
  extractProviderUIDs,
} from "@/lib/provider-helpers";
import { ProviderProps, ScanProps, SearchParamsProps } from "@/types";

export default async function Scans({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const session = await auth();
  const resolvedSearchParams = await searchParams;
  const filteredParams = { ...resolvedSearchParams };
  delete filteredParams.scanId;

  const providersData = await getAllProviders();

  const providerInfo =
    providersData?.data
      ?.filter(
        (provider: ProviderProps) =>
          provider.attributes.connection.connected === true,
      )
      .map((provider: ProviderProps) => ({
        providerId: provider.id,
        alias: provider.attributes.alias,
        providerType: provider.attributes.provider,
        uid: provider.attributes.uid,
        connected: provider.attributes.connection.connected,
      })) || [];

  const thereIsNoProviders =
    !providersData?.data || providersData.data.length === 0;

  const thereIsNoProvidersConnected = providersData?.data?.every(
    (provider: ProviderProps) => !provider.attributes.connection.connected,
  );

  const hasManageScansPermission = session?.user?.permissions?.manage_scans;

  // Get scans data to check for executing scans
  const scansData = await getScansByState();

  const hasExecutingScan = scansData?.data?.some(
    (scan: ScanProps) =>
      scan.attributes.state === "executing" ||
      scan.attributes.state === "available",
  );

  // Extract provider UIDs and create provider details mapping for filtering
  const providerUIDs = providersData ? extractProviderUIDs(providersData) : [];
  const providerDetails = providersData
    ? createProviderDetailsMapping(providerUIDs, providersData)
    : [];

  if (thereIsNoProviders) {
    return (
      <ContentLayout title="Scans" icon="lucide:timer">
        <NoProvidersAdded />
      </ContentLayout>
    );
  }

  return (
    <ContentLayout title="Scans" icon="lucide:timer">
      <AutoRefresh hasExecutingScan={hasExecutingScan} />
      <>
        <>
          {!hasManageScansPermission ? (
            <CustomBanner
              title={"Access Denied"}
              message={"You don't have permission to launch the scan."}
            />
          ) : thereIsNoProvidersConnected ? (
            <>
              <NoProvidersConnected />
            </>
          ) : (
            <LaunchScanWorkflow providers={providerInfo} />
          )}
        </>
        <div className="flex flex-col gap-6">
          <ScansFilters
            providerUIDs={providerUIDs}
            providerDetails={providerDetails}
          />
          <div className="flex items-center justify-end">
            <MutedFindingsConfigButton />
          </div>
          <Suspense fallback={<SkeletonTableScans />}>
            <SSRDataTableScans searchParams={resolvedSearchParams} />
          </Suspense>
        </div>
      </>
    </ContentLayout>
  );
}

const SSRDataTableScans = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() || "10", 10);
  const sort = searchParams.sort?.toString();

  // Extract all filter parameters, excluding scanId
  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(
      ([key]) => key.startsWith("filter[") && key !== "scanId",
    ),
  );

  // Extract query from filters
  const query = (filters["filter[search]"] as string) || "";

  // Fetch scans data with provider information included
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

      if (!providerId) {
        return { ...scan, providerInfo: null };
      }

      // Find the provider data in the included array
      const providerData = included?.find(
        (item: { type: string; id: string }) =>
          item.type === "providers" && item.id === providerId,
      );

      if (!providerData) {
        return { ...scan, providerInfo: null };
      }

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
    <DataTable
      key={`scans-${Date.now()}`}
      columns={ColumnGetScans}
      data={expandedScansData || []}
      metadata={meta}
    />
  );
};
