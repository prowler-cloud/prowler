import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProvider, getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { filterScans } from "@/components/filters";
import {
  ButtonRefreshData,
  NoProvidersAdded,
  NoProvidersConnected,
} from "@/components/scans";
import { LaunchScanWorkflow } from "@/components/scans/launch-workflow";
import { SkeletonTableScans } from "@/components/scans/table";
import { ColumnGetScans } from "@/components/scans/table/scans";
import { Header } from "@/components/ui";
import { DataTable, DataTableFilterCustom } from "@/components/ui/table";
import { ProviderProps, SearchParamsProps } from "@/types";

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
  });

  const providerInfo =
    providersData?.data.map((provider: ProviderProps) => ({
      providerId: provider.id,
      alias: provider.attributes.alias,
      providerType: provider.attributes.provider,
      uid: provider.attributes.uid,
      connected: provider.attributes.connection.connected,
    })) || [];

  const providersCountConnected = await getProviders({});
  const thereIsNoProviders =
    !providersCountConnected?.data || providersCountConnected.data.length === 0;

  const thereIsNoProvidersConnected = providersCountConnected?.data?.every(
    (provider: ProviderProps) => !provider.attributes.connection.connected,
  );

  return (
    <>
      <Header title="Scans" icon="lucide:scan-search" />

      {thereIsNoProviders && (
        <>
          <Spacer y={4} />
          <NoProvidersAdded />
        </>
      )}

      {!thereIsNoProviders && (
        <>
          {thereIsNoProvidersConnected ? (
            <>
              <Spacer y={8} />
              <NoProvidersConnected />
            </>
          ) : (
            <>
              <LaunchScanWorkflow providers={providerInfo} />
              <Spacer y={8} />
            </>
          )}
          <Spacer y={8} />
          <div className="grid grid-cols-12 items-start gap-4">
            <div className="col-span-12">
              <div className="flex flex-row items-center justify-between">
                <DataTableFilterCustom filters={filterScans || []} />
                <ButtonRefreshData
                  onPress={async () => {
                    "use server";
                    await getScans({});
                  }}
                />
              </div>
              <Spacer y={8} />
              <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
                <SSRDataTableScans searchParams={searchParams} />
              </Suspense>
            </div>
          </div>
        </>
      )}
    </>
  );
}

const SSRDataTableScans = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const page = parseInt(searchParams.page?.toString() || "1", 10);
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
  const scansData = await getScans({ query, page, sort, filters });

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
