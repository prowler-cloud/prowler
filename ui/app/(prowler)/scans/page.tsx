import { Suspense } from "react";

import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { auth } from "@/auth.config";
import { ScansPageShell } from "@/components/scans/scans-page-shell";
import {
  getScanJobsTab,
  getScanJobsTabFilters,
  isScanStateFilterKey,
} from "@/components/scans/scans-table.utils";
import { SkeletonTableScans } from "@/components/scans/table";
import { ScanJobsTable } from "@/components/scans/table/scans/scan-jobs-table";
import { ContentLayout } from "@/components/ui";
import { ProviderProps, ScanProps, SearchParamsProps } from "@/types";

export default async function Scans({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const session = await auth();
  const resolvedSearchParams = await searchParams;

  const providersData = await getAllProviders();

  const connectedProviders =
    providersData?.data?.filter(
      (provider: ProviderProps) =>
        provider.attributes.connection.connected === true,
    ) || [];

  const hasManageScansPermission = Boolean(
    session?.user?.permissions?.manage_scans,
  );

  return (
    <ContentLayout title="Scan Jobs" icon="lucide:timer">
      <ScansPageShell
        providers={connectedProviders}
        hasManageScansPermission={hasManageScansPermission}
      >
        <Suspense fallback={<SkeletonTableScans />}>
          <SSRDataTableScans searchParams={resolvedSearchParams} />
        </Suspense>
      </ScansPageShell>
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

  const filters = {
    ...Object.fromEntries(
      Object.entries(searchParams).filter(
        ([key]) => key.startsWith("filter[") && !isScanStateFilterKey(key),
      ),
    ),
    ...getScanJobsTabFilters(tab),
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

  return <ScanJobsTable data={expandedScansData} meta={meta} tab={tab} />;
};
