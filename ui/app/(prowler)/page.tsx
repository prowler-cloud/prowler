import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getFindings } from "@/actions/findings/findings";
import {
  getFindingsByStatus,
  getProvidersOverview,
} from "@/actions/overview/overview";
import { FilterControls } from "@/components/filters";
import {
  FindingsByStatusChart,
  LinkToFindings,
  ProvidersOverview,
  SkeletonFindingsByStatusChart,
  SkeletonProvidersOverview,
} from "@/components/overview";
import { ColumnNewFindingsToDate } from "@/components/overview/new-findings-table/table/column-new-findings-to-date";
import { SkeletonTableNewFindings } from "@/components/overview/new-findings-table/table/skeleton-table-new-findings";
import { Header } from "@/components/ui";
import { DataTable } from "@/components/ui/table";
import { SearchParamsProps } from "@/types";

export default function Home({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});
  return (
    <>
      <Header title="Scan Overview" icon="solar:pie-chart-2-outline" />
      <Spacer y={4} />
      <FilterControls providers regions date />
      <div className="min-h-screen">
        <div className="container mx-auto space-y-8 px-0 py-6">
          {/* Providers Overview, Chart and New Findings Table */}
          <div className="grid grid-cols-12 gap-6">
            <div className="col-span-12 lg:col-span-3">
              <Suspense fallback={<SkeletonProvidersOverview />}>
                <SSRProvidersOverview />
              </Suspense>
            </div>

            {/* Findings by Status */}
            <div className="col-span-12 lg:col-span-4">
              <Suspense fallback={<SkeletonFindingsByStatusChart />}>
                <SSRFindingsByStatus searchParams={searchParams} />
              </Suspense>
            </div>

            <div className="col-span-12 lg:col-span-5">
              <Suspense
                key={searchParamsKey}
                fallback={<SkeletonTableNewFindings />}
              >
                <SSRDataNewFindingsTable />
              </Suspense>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

const SSRProvidersOverview = async () => {
  const providersOverview = await getProvidersOverview({});

  return (
    <>
      <h3 className="mb-4 text-sm font-bold">Providers Overview</h3>
      <ProvidersOverview providersOverview={providersOverview} />
    </>
  );
};

const SSRFindingsByStatus = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = searchParams
    ? Object.fromEntries(
        Object.entries(searchParams).filter(([key]) =>
          key.startsWith("filter["),
        ),
      )
    : {};

  const findingsByStatus = await getFindingsByStatus({ filters });

  return (
    <>
      <h3 className="mb-4 text-sm font-bold">Findings by Status</h3>
      <FindingsByStatusChart findingsByStatus={findingsByStatus} />
    </>
  );
};

const SSRDataNewFindingsTable = async () => {
  // Temporarily disabled search params handling
  // const page = parseInt(searchParams.page?.toString() || "1", 10);
  // const sort = searchParams.sort?.toString();
  const page = 1;
  const sort = undefined;

  // Extract all filter parameters
  // const filters = Object.fromEntries(
  //   Object.entries(searchParams).filter(([key]) => key.startsWith("filter[")),
  // );

  // const defaultFilters =
  //   Object.keys(filters).length === 0
  //     ? {
  const defaultFilters = {
    "filter[severity]": "critical",
    "filter[delta__in]": "new",
    "filter[status__in]": "FAIL",
  };
  // : {};

  const finalFilters = {
    ...defaultFilters,
    // ...filters,  // Temporarily disabled additional filters
  } as Record<string, string>;

  // const query = finalFilters["filter[search]"];
  const query = undefined;

  const findingsData = await getFindings({
    query,
    page,
    sort,
    filters: finalFilters,
  });

  return (
    <>
      <div className="relative flex items-start justify-between">
        <h3 className="mb-4 w-full text-sm font-bold">
          New failing findings to date
        </h3>
        <div className="absolute -top-6 right-0">
          <LinkToFindings />
        </div>
      </div>
      <DataTable
        columns={ColumnNewFindingsToDate}
        data={findingsData?.data || []}
        metadata={findingsData?.meta}
      />
    </>
  );
};
