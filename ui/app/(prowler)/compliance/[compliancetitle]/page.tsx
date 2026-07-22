import { ChevronDownIcon } from "lucide-react";
import { notFound, redirect } from "next/navigation";
import { Suspense } from "react";

import {
  getComplianceAttributes,
  getComplianceOverviewMetadataInfo,
  getComplianceRequirements,
  getCompliancesOverview,
} from "@/actions/compliances";
import { getThreatScore } from "@/actions/overview";
import { getScan } from "@/actions/scans";
import {
  ClientAccordionWrapper,
  ComplianceDownloadContainer,
  ComplianceHeader,
  ComplianceWarming,
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
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import {
  getReportTypeForCompliance,
  pickLatestCisPerProvider,
} from "@/lib/compliance/compliance-report-types";
import { isCloud } from "@/lib/shared/env";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";
import {
  AttributesData,
  Framework,
  RequirementsTotals,
} from "@/types/compliance";
import { isKnownProviderType } from "@/types/providers";
import { ScanEntity } from "@/types/scans";

import { CrossAccountDetail } from "../_components/cross-account-detail";
import { CrossProviderDetail } from "../_components/cross-provider-detail";
import { resolveCrossProviderFramework } from "../_lib/cross-provider-frameworks";
import { buildSearchParamsKey } from "../_lib/search-params-key";

const getSingleSearchParam = (
  value: string | string[] | undefined,
): string | undefined =>
  typeof value === "string" && value ? value : undefined;

export default async function ComplianceDetail({
  params,
  searchParams,
}: {
  params: Promise<{ compliancetitle: string }>;
  searchParams: Promise<SearchParamsProps>;
}) {
  const { compliancetitle } = await params;
  const resolvedSearchParams = await searchParams;
  const complianceId = getSingleSearchParam(resolvedSearchParams.complianceId);
  const version = getSingleSearchParam(resolvedSearchParams.version);
  const scanId = getSingleSearchParam(resolvedSearchParams.scanId);
  const section = getSingleSearchParam(resolvedSearchParams.section);
  const mode = getSingleSearchParam(resolvedSearchParams.mode);

  if (!complianceId) {
    notFound();
  }

  // Cross-provider mode replaces the per-scan pipeline with the universal
  // roll-up view. Prowler Cloud-only: the OSS API has no such endpoint, so
  // the route is blocked in OSS the same way the compliance tab is.
  if (mode === "cross-provider") {
    if (!isCloud()) {
      redirect("/compliance");
    }

    const framework = resolveCrossProviderFramework(
      complianceId,
      compliancetitle,
    );
    if (!framework) {
      notFound();
    }

    const crossProviderTitle = framework.title.split("-").join(" ");
    return (
      <ContentLayout title={`${crossProviderTitle} - ${framework.version}`}>
        <Suspense
          key={buildSearchParamsKey(resolvedSearchParams)}
          fallback={
            <div className="flex flex-col gap-8">
              <div className="grid grid-cols-1 gap-6 md:grid-cols-[minmax(280px,400px)_1fr]">
                <RequirementsStatusCardSkeleton />
                <TopFailedSectionsCardSkeleton />
              </div>
              <SkeletonAccordion />
            </div>
          }
        >
          <CrossProviderDetail
            compliancetitle={compliancetitle}
            complianceId={complianceId}
            searchParams={resolvedSearchParams}
            targetSection={section}
          />
        </Suspense>
      </ContentLayout>
    );
  }
  // Cross-account mode: one regular framework aggregated across every
  // account of one provider type. Cloud-only, like cross-provider.
  if (mode === "cross-account") {
    if (!isCloud()) {
      redirect("/compliance");
    }

    const providerType = getSingleSearchParam(
      resolvedSearchParams.providerType,
    );
    if (!providerType || !isKnownProviderType(providerType)) {
      notFound();
    }

    const crossAccountTitle = compliancetitle.split("-").join(" ");
    return (
      <ContentLayout
        title={
          version ? `${crossAccountTitle} - ${version}` : crossAccountTitle
        }
      >
        <Suspense
          key={buildSearchParamsKey(resolvedSearchParams)}
          fallback={
            <div className="flex flex-col gap-8">
              <div className="grid grid-cols-1 gap-6 md:grid-cols-[minmax(280px,400px)_1fr]">
                <RequirementsStatusCardSkeleton />
                <TopFailedSectionsCardSkeleton />
              </div>
              <SkeletonAccordion />
            </div>
          }
        >
          <CrossAccountDetail
            compliancetitle={compliancetitle}
            complianceId={complianceId}
            providerType={providerType}
            searchParams={resolvedSearchParams}
            targetSection={section}
          />
        </Suspense>
      </ContentLayout>
    );
  }

  const regionFilter = getSingleSearchParam(
    resolvedSearchParams["filter[region__in]"],
  );
  const cisProfileFilter = getSingleSearchParam(
    resolvedSearchParams["filter[cis_profile_level]"],
  );
  const logoPath = getComplianceIcon(compliancetitle);

  const searchParamsKey = buildSearchParamsKey(resolvedSearchParams);

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
      {/* Header card — same surface as the cross-provider detail: scan info
          and filters on the left, report actions and framework logo on the
          right (lighthouse-settings card pattern). */}
      <Card variant="base" className="mb-6 w-full gap-4 p-4 md:p-5">
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
                presentation="dropdown"
                dropdownTrigger={
                  <Button variant="outline">
                    Report
                    <ChevronDownIcon />
                  </Button>
                }
                reportType={getReportTypeForCompliance(
                  attributesData?.data?.[0]?.attributes?.framework,
                  complianceId,
                  latestCisIds.has(complianceId),
                )}
              />
            </div>
          )}
        </div>
      </Card>

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

      <ClientAccordionWrapper
        hideExpandButton={complianceId.includes("mitre_attack")}
        items={accordionItems}
        defaultExpandedKeys={initialExpandedKeys}
        scrollToKey={initialExpandedKeys[0]}
      />
    </div>
  );
};
