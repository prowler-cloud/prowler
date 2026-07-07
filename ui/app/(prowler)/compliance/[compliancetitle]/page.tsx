import { Spacer } from "@heroui/spacer";
import { Info } from "lucide-react";
import { redirect } from "next/navigation";
import { Suspense } from "react";

import {
  getComplianceAttributes,
  getComplianceOverviewMetadataInfo,
  getComplianceRequirements,
  getCompliancesOverview,
  getCrossProviderComplianceOverview,
  getLatestCrossProviderCompliancePdf,
} from "@/actions/compliances";
import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getThreatScore } from "@/actions/overview";
import { getAllProviders } from "@/actions/providers";
import { getScan } from "@/actions/scans";
import {
  ClientAccordionWrapper,
  ComplianceDownloadContainer,
  ComplianceHeader,
  ComplianceWarming,
  CrossProviderDetail,
  RequirementsStatusCard,
  RequirementsStatusCardSkeleton,
  // SectionsFailureRateCard,
  // SectionsFailureRateCardSkeleton,
  SkeletonAccordion,
  ThreatScoreBreakdownCard,
  ThreatScoreBreakdownCardSkeleton,
  TopFailedSectionsCard,
  TopFailedSectionsCardSkeleton,
} from "@/components/compliance";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { ContentLayout } from "@/components/ui";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import {
  getReportTypeForCompliance,
  pickLatestCisPerProvider,
} from "@/lib/compliance/compliance-report-types";
import { UNIVERSAL_FRAMEWORKS } from "@/lib/compliance/universal-frameworks";
import { isCloud } from "@/lib/shared/env";
import { cn } from "@/lib/utils";
import {
  AttributesData,
  CrossProviderComplianceOverviewData,
  Framework,
  RequirementsTotals,
} from "@/types/compliance";
import { ScanEntity } from "@/types/scans";

interface ComplianceDetailSearchParams {
  complianceId: string;
  version?: string;
  scanId?: string;
  section?: string;
  mode?: string;
  "filter[region__in]"?: string;
  "filter[provider_type__in]"?: string;
  "filter[provider_id__in]"?: string;
  "filter[provider_groups__in]"?: string;
  "filter[cis_profile_level]"?: string;
  page?: string;
  pageSize?: string;
}

export default async function ComplianceDetail({
  params,
  searchParams,
}: {
  params: Promise<{ compliancetitle: string }>;
  searchParams: Promise<ComplianceDetailSearchParams>;
}) {
  const { compliancetitle } = await params;
  const resolvedSearchParams = await searchParams;
  const { complianceId, version, scanId, section, mode } = resolvedSearchParams;
  const regionFilter = resolvedSearchParams["filter[region__in]"];
  const providerTypeFilter = resolvedSearchParams["filter[provider_type__in]"];
  const providerIdFilter = resolvedSearchParams["filter[provider_id__in]"];
  const providerGroupsFilter =
    resolvedSearchParams["filter[provider_groups__in]"];
  const cisProfileFilter = resolvedSearchParams["filter[cis_profile_level]"];
  const logoPath = getComplianceIcon(compliancetitle);

  // Cross-provider mode: skip the per-scan pipeline and render the
  // cross-provider universal compliance roll-up instead. This is a Prowler
  // Cloud-only feature (the OSS API has no cross-provider-compliance-overviews
  // endpoint), so block the route in OSS the same way Alerts/Scan
  // Configuration do.
  if (mode === "cross-provider") {
    if (!isCloud()) {
      redirect("/compliance");
    }

    const crossProviderTitle = compliancetitle.split("-").join(" ");
    const [
      crossProviderResponse,
      providersData,
      providerGroupsData,
      latestPdfReport,
    ] = await Promise.all([
      getCrossProviderComplianceOverview({
        complianceId,
        providerTypes: providerTypeFilter,
        providerIds: providerIdFilter,
        providerGroups: providerGroupsFilter,
        regions: regionFilter,
      }),
      getAllProviders(),
      getAllProviderGroups(),
      // Independent of the overview fetch above — the backend resolves the
      // same "latest scan per filtered provider" rule from these same raw
      // filters, so this can run in parallel instead of waterfalling behind
      // the overview response just to read its resolved scan_ids.
      getLatestCrossProviderCompliancePdf({
        complianceId,
        providerTypes: providerTypeFilter,
        providerIds: providerIdFilter,
        providerGroups: providerGroupsFilter,
      }),
    ]);

    if (!crossProviderResponse || "redirectTo" in crossProviderResponse) {
      // A 402 (payment required) resolves to ``{ redirectTo: "/billing" }`` —
      // send the user to the upgrade prompt instead of the generic
      // "not available" state, which would swallow the billing signal.
      if (
        crossProviderResponse &&
        "redirectTo" in crossProviderResponse &&
        crossProviderResponse.redirectTo
      ) {
        redirect(crossProviderResponse.redirectTo);
      }
      return (
        <ContentLayout title={crossProviderTitle}>
          <Alert variant="info">
            <Info className="size-4" />
            <AlertDescription>
              Cross-provider data is not available for this framework yet.
            </AlertDescription>
          </Alert>
        </ContentLayout>
      );
    }

    const crossProviderData = (
      crossProviderResponse as {
        data?: CrossProviderComplianceOverviewData;
      }
    ).data;

    if (!crossProviderData) {
      return (
        <ContentLayout title={crossProviderTitle}>
          <Alert variant="info">
            <Info className="size-4" />
            <AlertDescription>
              No cross-provider compliance data was returned for this framework.
            </AlertDescription>
          </Alert>
        </ContentLayout>
      );
    }

    const headerTitle = crossProviderData.attributes.name || crossProviderTitle;
    // ``compatible_providers`` from the API is authoritative; fall back to the
    // ``UNIVERSAL_FRAMEWORKS`` catalogue entry when it's missing or empty, so
    // the detail view and provider filters stay populated — matching the
    // overview grid's behavior instead of dropping every provider.
    const apiCompatibleProviders =
      crossProviderData.attributes.compatible_providers;
    const catalogueProviders =
      UNIVERSAL_FRAMEWORKS.find((entry) => entry.id === complianceId)
        ?.providers ?? [];
    const compatibleProviderTypes = new Set(
      apiCompatibleProviders && apiCompatibleProviders.length > 0
        ? apiCompatibleProviders
        : catalogueProviders,
    );
    const compatibleProviders = (providersData?.data || []).filter((provider) =>
      compatibleProviderTypes.has(provider.attributes.provider),
    );
    return (
      <ContentLayout title={headerTitle}>
        <CrossProviderDetail
          attributes={crossProviderData.attributes}
          providers={compatibleProviders}
          providerGroups={providerGroupsData?.data || []}
          providerTypeFilter={providerTypeFilter}
          providerIdFilter={providerIdFilter}
          providerGroupsFilter={providerGroupsFilter}
          latestPdfReport={
            "available" in latestPdfReport && latestPdfReport.available
              ? latestPdfReport
              : null
          }
        />
      </ContentLayout>
    );
  }

  // Create a key that excludes pagination parameters to preserve accordion state avoiding reloads with pagination
  const paramsForKey = Object.fromEntries(
    Object.entries(resolvedSearchParams).filter(
      ([key]) => key !== "page" && key !== "pageSize",
    ),
  );
  const searchParamsKey = JSON.stringify(paramsForKey);

  const formattedTitle = compliancetitle.split("-").join(" ");
  const pageTitle = version
    ? `${formattedTitle} - ${version}`
    : `${formattedTitle}`;

  let selectedScan: ScanEntity | null = null;
  const selectedScanId = scanId || null;

  const [metadataInfoData, attributesData, selectedScanResponse] =
    await Promise.all([
      getComplianceOverviewMetadataInfo({
        filters: {
          "filter[scan_id]": selectedScanId ?? undefined,
        },
      }),
      getComplianceAttributes(complianceId, selectedScanId ?? undefined),
      selectedScanId
        ? getScan(selectedScanId, { include: "provider" })
        : Promise.resolve(null),
    ]);

  // The compliance catalog is still warming after a deploy/restart. Show the
  // "still loading" state with a Try Again instead of rendering an empty page.
  if (attributesData?.warming) {
    return (
      <ContentLayout title={pageTitle}>
        <ComplianceWarming />
      </ContentLayout>
    );
  }

  if (selectedScanResponse?.data) {
    const scan = selectedScanResponse.data;
    const providerId = scan.relationships?.provider?.data?.id;
    const providerData = providerId
      ? selectedScanResponse.included?.find(
          (item: { type: string; id: string }) =>
            item.type === "providers" && item.id === providerId,
        )
      : undefined;

    if (providerData) {
      selectedScan = {
        id: scan.id,
        providerInfo: {
          provider: providerData.attributes.provider,
          alias: providerData.attributes.alias,
          uid: providerData.attributes.uid,
        },
        attributes: {
          name: scan.attributes.name,
          completed_at: scan.attributes.completed_at,
        },
      };
    }
  }

  // Only CIS variants need the "is this the latest version per provider?"
  // check to gate the PDF download button. Every other framework either
  // always has a PDF (ENS/NIS2/CSA/ThreatScore) or none at all, so we skip
  // the extra compliance-overview roundtrip for non-CIS detail pages.
  const needsCisLatestCheck =
    typeof complianceId === "string" && complianceId.startsWith("cis_");
  let latestCisIds: Set<string> = new Set<string>();
  if (needsCisLatestCheck && selectedScanId) {
    const scanCompliancesData = await getCompliancesOverview({
      scanId: selectedScanId,
    });
    const scanComplianceIds: string[] = Array.isArray(scanCompliancesData?.data)
      ? scanCompliancesData.data
          .map((c: { id?: string }) => c?.id)
          .filter(
            (id: string | undefined): id is string => typeof id === "string",
          )
      : [];
    latestCisIds = pickLatestCisPerProvider(scanComplianceIds);
  }

  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];

  // Detect if this is a ThreatScore compliance view
  const isThreatScore = complianceId?.includes("prowler_threatscore");

  // Fetch ThreatScore data if applicable
  let threatScoreData = null;
  if (isThreatScore && selectedScanId) {
    const threatScoreResponse = await getThreatScore({
      filters: { "filter[scan_id]": selectedScanId },
    });

    if (threatScoreResponse?.data && threatScoreResponse.data.length > 0) {
      const snapshot = threatScoreResponse.data[0];
      threatScoreData = {
        overallScore: parseFloat(snapshot.attributes.overall_score),
        sectionScores: snapshot.attributes.section_scores,
      };
    }
  }

  // Use compliance_name from attributes if available, otherwise fallback to formatted title
  const complianceName = attributesData?.data?.[0]?.attributes?.compliance_name;
  const finalPageTitle = complianceName ? `${complianceName}` : pageTitle;

  return (
    <ContentLayout title={finalPageTitle}>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0 flex-1">
          <ComplianceHeader
            scans={[]}
            uniqueRegions={uniqueRegions}
            showSearch={false}
            framework={compliancetitle}
            showProviders={false}
            logoPath={logoPath}
            complianceTitle={compliancetitle}
            selectedScan={selectedScan}
          />
        </div>
        {selectedScanId && (
          <div className="mb-4 flex-shrink-0 self-end sm:mb-0 sm:self-start sm:pt-1">
            <ComplianceDownloadContainer
              scanId={selectedScanId}
              complianceId={complianceId}
              reportType={getReportTypeForCompliance(
                attributesData?.data?.[0]?.attributes?.framework,
                complianceId,
                latestCisIds.has(complianceId),
              )}
            />
          </div>
        )}
      </div>

      <Suspense
        key={searchParamsKey}
        fallback={
          <div className="flex flex-col gap-8">
            {/* Mobile: each card on own row | Tablet: ThreatScore full row, others share row | Desktop: all 3 in one row */}
            <div
              className={cn(
                "grid grid-cols-1 gap-6 md:grid-cols-[minmax(280px,400px)_1fr]",
                isThreatScore &&
                  "xl:grid-cols-[minmax(280px,320px)_minmax(280px,400px)_1fr]",
              )}
            >
              {isThreatScore && (
                <div className="md:col-span-2 xl:col-span-1">
                  <ThreatScoreBreakdownCardSkeleton />
                </div>
              )}
              <RequirementsStatusCardSkeleton />
              <TopFailedSectionsCardSkeleton />
              {/* <SectionsFailureRateCardSkeleton /> */}
            </div>
            <SkeletonAccordion />
          </div>
        }
      >
        <SSRComplianceContent
          complianceId={complianceId}
          scanId={selectedScanId || ""}
          region={regionFilter}
          filter={cisProfileFilter}
          attributesData={attributesData}
          threatScoreData={threatScoreData}
          targetSection={section}
        />
      </Suspense>
    </ContentLayout>
  );
}

const SSRComplianceContent = async ({
  complianceId,
  scanId,
  region,
  filter,
  attributesData,
  threatScoreData,
  targetSection,
}: {
  complianceId: string;
  scanId: string;
  region?: string;
  filter?: string;
  attributesData: AttributesData;
  threatScoreData: {
    overallScore: number;
    sectionScores: Record<string, number>;
  } | null;
  targetSection?: string;
}) => {
  const requirementsData = await getComplianceRequirements({
    complianceId,
    scanId,
    region,
  });
  const type = requirementsData?.data?.[0]?.type;

  if (!scanId || type === "tasks") {
    return (
      <div className="flex flex-col gap-8">
        <div className="grid grid-cols-1 gap-6 md:grid-cols-[minmax(280px,400px)_1fr]">
          <RequirementsStatusCard pass={0} fail={0} manual={0} />
          <TopFailedSectionsCard sections={[]} />
          {/* <SectionsFailureRateCard categories={[]} /> */}
        </div>
        <ClientAccordionWrapper items={[]} defaultExpandedKeys={[]} />
      </div>
    );
  }

  const framework = attributesData?.data?.[0]?.attributes?.framework;
  const mapper = getComplianceMapper(framework);
  const data = mapper.mapComplianceData(
    attributesData,
    requirementsData,
    filter,
  );
  // const categoryHeatmapData = mapper.calculateCategoryHeatmapData(data);
  const totalRequirements: RequirementsTotals = data.reduce(
    (acc: RequirementsTotals, framework: Framework) => ({
      pass: acc.pass + framework.pass,
      fail: acc.fail + framework.fail,
      manual: acc.manual + framework.manual,
    }),
    { pass: 0, fail: 0, manual: 0 },
  );
  const accordionItems = mapper.toAccordionItems(data, scanId);
  const topFailedResult = mapper.getTopFailedSections(data);

  // Resolve which accordion key matches the requested ?section= so we can
  // auto-expand it on first render. Each mapper builds keys as
  // `${framework.name}-${category.name}`; rebuild the exact candidates here
  // to avoid suffix collisions across frameworks or category names.
  const initialExpandedKeys: string[] = [];
  if (targetSection) {
    const candidates = new Set(
      data.map((f: Framework) => `${f.name}-${targetSection}`),
    );
    const match = accordionItems.find((item) => candidates.has(item.key));
    if (match) {
      initialExpandedKeys.push(match.key);
    }
  }

  return (
    <div className="flex flex-col gap-8">
      {/* Charts section */}
      {/* Mobile: each card on own row | Tablet: ThreatScore full row, others share row | Desktop: all 3 in one row */}
      <div
        className={cn(
          "grid grid-cols-1 gap-6 md:grid-cols-[minmax(280px,400px)_1fr]",
          threatScoreData &&
            "xl:grid-cols-[minmax(280px,320px)_minmax(280px,400px)_1fr]",
        )}
      >
        {threatScoreData && (
          <div className="md:col-span-2 xl:col-span-1">
            <ThreatScoreBreakdownCard
              overallScore={threatScoreData.overallScore}
              sectionScores={threatScoreData.sectionScores}
            />
          </div>
        )}
        <RequirementsStatusCard
          pass={totalRequirements.pass}
          fail={totalRequirements.fail}
          manual={totalRequirements.manual}
        />
        <TopFailedSectionsCard
          sections={topFailedResult.items}
          dataType={topFailedResult.type}
          prepopulated={topFailedResult.prepopulated}
        />
        {/* <SectionsFailureRateCard categories={categoryHeatmapData} /> */}
      </div>

      <Spacer className="bg-border-neutral-primary h-1 w-full rounded-full" />
      <ClientAccordionWrapper
        hideExpandButton={complianceId.includes("mitre_attack")}
        items={accordionItems}
        defaultExpandedKeys={initialExpandedKeys}
        scrollToKey={initialExpandedKeys[0]}
      />
    </div>
  );
};
