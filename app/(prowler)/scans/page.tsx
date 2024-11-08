import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { filterScans } from "@/components/filters";
import { LaunchScanWorkflow } from "@/components/scans/launch-workflow";
import { SkeletonTableScans } from "@/components/scans/table";
import { ColumnGetScans } from "@/components/scans/table/scans";
import { Header } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { ProviderProps, SearchParamsProps } from "@/types";

export default async function Scans({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});
  // const providersData = await getProviders({
  //   filters: { "filter[connected]": "true" },
  // });
  const providersData = await getProviders({});

  const providerInfo = providersData?.data?.length
    ? providersData.data.map((provider: ProviderProps) => ({
        providerId: provider.id,
        alias: provider.attributes.alias,
        providerType: provider.attributes.provider,
        uid: provider.attributes.uid,
        connected: provider.attributes.connection.connected,
      }))
    : [];

  return (
    <>
      <Header title="Scans" icon="lucide:scan-search" />

      <Spacer y={4} />
      <LaunchScanWorkflow providers={providerInfo} />
      <Spacer y={8} />

      <div className="grid grid-cols-12 items-start gap-4">
        <div className="col-span-12">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
            <SSRDataTableScans searchParams={searchParams} />
          </Suspense>
        </div>
      </div>
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

  // Extract all filter parameters
  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  );

  // Extract query from filters
  const query = (filters["filter[search]"] as string) || "";

  const scansData = await getScans({ query, page, sort, filters });

  return (
    <DataTable
      columns={ColumnGetScans}
      data={scansData?.data || []}
      metadata={scansData?.meta}
      customFilters={filterScans}
    />
  );
};
