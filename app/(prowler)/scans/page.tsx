import { Link, Spacer, Tooltip } from "@nextui-org/react";
import { Suspense } from "react";

import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { filterScans } from "@/components/filters";
import { InfoIcon } from "@/components/icons";
import { LaunchScanWorkflow } from "@/components/scans/launch-workflow";
import { SkeletonTableScans } from "@/components/scans/table";
import { ColumnProviderScans } from "@/components/scans/table/provider-scans";
import { ColumnGetScans } from "@/components/scans/table/scans";
import { Header } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { SearchParamsProps } from "@/types";

export default async function Scans({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="Scans" icon="lucide:scan-search" />

      <Spacer y={4} />
      <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
        <LaunchScanWorkflow />
      </Suspense>
      <Spacer y={8} />

      <div className="grid grid-cols-12 items-start gap-4">
        <div className="col-span-12">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
            <SSRDataTableScans searchParams={searchParams} />
          </Suspense>
        </div>
        <div className="col-span-12 lg:col-span-6">
          <Suspense key={searchParamsKey} fallback={<SkeletonTableScans />}>
            <SSRDataTableProviders />
          </Suspense>
        </div>
      </div>
    </>
  );
}

const SSRDataTableProviders = async () => {
  const providersData = await getProviders({
    filters: { "filter[connected]": "true" },
  });
  return (
    <>
      <div className="mb-2 flex items-center gap-2">
        <Tooltip content="Only connected providers can be scanned">
          <InfoIcon size={16} />
        </Tooltip>
        <p className="text-sm text-default-500">Connected providers</p>
      </div>
      <DataTable
        columns={ColumnProviderScans}
        data={providersData?.data || []}
      />
      <p className="-mt-4 text-sm text-default-500">
        If you don't see any providers, please check your connection settings on
        the{" "}
        <Link className="text-sm font-medium" href="/providers">
          providers page
        </Link>
        .
      </p>
    </>
  );
};

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
