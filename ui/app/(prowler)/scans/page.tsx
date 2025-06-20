import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProvider, getProviders } from "@/actions/providers";
import { getScans, getScansByState } from "@/actions/scans";
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
import { DataTable } from "@/components/ui/table";
import {
  createProviderDetailsMapping,
  extractProviderUIDs,
} from "@/lib/provider-helpers";
import { ProviderProps, ScanProps, SearchParamsProps } from "@/types";

export default async function Scans({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const filteredParams = { ...searchParams };
  delete filteredParams.scanId;
  const searchParamsKey = JSON.stringify(filteredParams);

  const providersData = await getProviders({
    filters: {
      "filter[connected]": true,
    },
    pageSize: 50,
  });

  const providerInfo =
    providersData?.data?.map((provider: ProviderProps) => ({
      providerId: provider.id,
      alias: provider.attributes.alias,
      providerType: provider.attributes.provider,
      uid: provider.attributes.uid,
      connected: provider.attributes.connection.connected,
    })) || [];

  const providersCountConnected = await getProviders({
    filters: { "filter[connected]": true },
    pageSize: 50,
  });
  const thereIsNoProviders = !providersCountConnected?.data;

  const thereIsNoProvidersConnected = providersCountConnected?.data?.every(
    (provider: ProviderProps) => !provider.attributes.connection.connected,
  );

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
      <ContentLayout title="Scans" icon="lucide:scan-search">
        <NoProvidersAdded />
      </ContentLayout>
    );
  }

  return (
    <ContentLayout title="Scans" icon="lucide:scan-search">
      <AutoRefresh hasExecutingScan={hasExecutingScan} />
      <>
        {thereIsNoProvidersConnected ? (
          <>
            <Spacer y={8} />
            <NoProvidersConnected />
            <Spacer y={8} />
          </>
        ) : (
          <LaunchScanWorkflow providers={providerInfo} />
        )}
        <ScansFilters
          providerUIDs={providerUIDs}
          providerDetails={providerDetails}
        />
        <Spacer y={8} />
        <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
          <SSRDataTableScans searchParams={searchParams} />
        </Suspense>
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

  // Fetch scans data
  const scansData = await getScans({ query, page, sort, filters, pageSize });

  // Handle expanded scans data
  const expandedScansData = await Promise.all(
    scansData?.data?.map(async (scan: any) => {
      const providerId = scan.relationships?.provider?.data?.id;

      if (!providerId) {
        return { ...scan, providerInfo: null };
      }

      const formData = new FormData();
      formData.append("id", providerId);

      const providerData = await getProvider(formData);

      if (providerData?.data) {
        const { provider, uid, alias } = providerData.data.attributes;
        return {
          ...scan,
          providerInfo: { provider, uid, alias },
        };
      }

      return { ...scan, providerInfo: null };
    }) || [],
  );

  return (
    <DataTable
      columns={ColumnGetScans}
      data={expandedScansData || []}
      metadata={scansData?.meta}
    />
  );
};
