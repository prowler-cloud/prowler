import { notFound } from "next/navigation";

import { getLatestMetadataInfo } from "@/actions/findings";
import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { getAlert, listAlerts } from "@/app/(prowler)/alerts/_actions";
import { AlertsManager } from "@/app/(prowler)/alerts/_components/alerts-manager";
import { isAlertsEnabled } from "@/app/(prowler)/alerts/_lib/env";
import { ContentLayout } from "@/components/ui";
import { createScanDetailsMapping } from "@/lib";
import type { MetaDataProps, ScanEntity, ScanProps } from "@/types";

interface AlertsPageProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

const getParamValue = (
  params: Awaited<AlertsPageProps["searchParams"]>,
  key: string,
): string | undefined => {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
};

const toAlertsSearchParams = (
  resolvedSearchParams: Awaited<AlertsPageProps["searchParams"]>,
): URLSearchParams => {
  const page = Number.parseInt(
    getParamValue(resolvedSearchParams, "page") ?? "1",
    10,
  );
  const pageSize = Number.parseInt(
    getParamValue(resolvedSearchParams, "pageSize") ?? "20",
    10,
  );
  const sort = getParamValue(resolvedSearchParams, "sort") ?? "-inserted_at";
  const search = getParamValue(resolvedSearchParams, "filter[search]") ?? "";
  const enabledFilter = getParamValue(resolvedSearchParams, "filter[enabled]");
  const triggerFilter = getParamValue(resolvedSearchParams, "filter[trigger]");

  const params = new URLSearchParams();
  params.set("page[number]", String(page));
  params.set("page[size]", String(pageSize));
  params.set("sort", sort);
  if (search) params.set("filter[search]", search);
  if (enabledFilter) params.set("filter[enabled]", enabledFilter);
  if (triggerFilter) params.set("filter[trigger]", triggerFilter);
  return params;
};

export default async function AlertsPage({ searchParams }: AlertsPageProps) {
  if (!isAlertsEnabled()) {
    notFound();
  }

  const resolvedSearchParams = await searchParams;
  const editAlertId = getParamValue(resolvedSearchParams, "edit");
  const [result, providersData, scansData, metadataInfoData, editResult] =
    await Promise.all([
      listAlerts(toAlertsSearchParams(resolvedSearchParams)),
      getProviders({ pageSize: 50 }),
      getScans({ pageSize: 50 }),
      getLatestMetadataInfo({}),
      editAlertId ? getAlert(editAlertId) : Promise.resolve(null),
    ]);
  const alerts = result.ok ? result.data.data : [];
  const apiMeta = result.ok ? result.data.meta : undefined;
  const loadError = !result.ok ? result.error.detail : null;
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];
  const uniqueServices = metadataInfoData?.data?.attributes?.services || [];
  const uniqueResourceTypes =
    metadataInfoData?.data?.attributes?.resource_types || [];
  const uniqueCategories = metadataInfoData?.data?.attributes?.categories || [];
  const uniqueGroups = metadataInfoData?.data?.attributes?.groups || [];
  const scans = scansData && "data" in scansData ? scansData.data : [];
  const completedScans = scans?.filter(
    (scan: ScanProps) =>
      scan.attributes.state === "completed" &&
      scan.attributes.unique_resource_count > 1,
  );
  const completedScanIds =
    completedScans?.map((scan: ScanProps) => scan.id) || [];
  const scanDetails = createScanDetailsMapping(
    completedScans || [],
    providersData,
  ) as { [uid: string]: ScanEntity }[];
  const editingAlert =
    editResult && editResult.ok ? editResult.data.data : null;
  const meta: MetaDataProps | undefined = apiMeta?.pagination
    ? {
        pagination: {
          page: apiMeta.pagination.page,
          pages: apiMeta.pagination.pages,
          count: apiMeta.pagination.count,
        },
        version: "1",
      }
    : undefined;

  return (
    <ContentLayout title="Alerts" icon="lucide:bell-ring">
      <AlertsManager
        alerts={alerts}
        meta={meta}
        loadError={loadError}
        providers={providersData?.data || []}
        completedScanIds={completedScanIds}
        scanDetails={scanDetails}
        uniqueRegions={uniqueRegions}
        uniqueServices={uniqueServices}
        uniqueResourceTypes={uniqueResourceTypes}
        uniqueCategories={uniqueCategories}
        uniqueGroups={uniqueGroups}
        initialEditingAlert={editingAlert}
      />
    </ContentLayout>
  );
}
