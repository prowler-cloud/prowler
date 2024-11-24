import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { filterScans } from "@/components/filters";
import { ButtonRefreshData } from "@/components/scans";
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

  // const executingScans = await getExecutingScans();

  return (
    <>
      <Header title="Scans" icon="lucide:scan-search" />

      <Spacer y={4} />
      <LaunchScanWorkflow providers={providerInfo} />
      <Spacer y={8} />
      <div className="flex flex-row justify-between">
        <DataTableFilterCustom filters={filterScans || []} />
        <ButtonRefreshData
          onPress={async () => {
            "use server";
            await getScans({});
          }}
        />
      </div>

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

  // Extract all filter parameters, excluding scanId
  const filters = Object.fromEntries(
    Object.entries(searchParams).filter(
      ([key]) => key.startsWith("filter[") && key !== "scanId",
    ),
  );

  // Extract query from filters
  const query = (filters["filter[search]"] as string) || "";

  const scansData = await getScans({ query, page, sort, filters });

  return (
    <DataTable
      columns={ColumnGetScans}
      data={scansData?.data || []}
      metadata={scansData?.meta}
    />
  );
};

// const getExecutingScans = async () => {
//   const scansData = await getScans({});

//   return scansData?.data?.some(
//     (scan: ScanProps) =>
//       scan.attributes.state === "executing" && scan.attributes.progress < 100,
//   );
// };
