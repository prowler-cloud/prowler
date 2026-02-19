import { Spacer } from "@heroui/spacer";
import { Suspense } from "react";

import {
  getComplianceAttributes,
  getComplianceOverviewMetadataInfo,
  getComplianceRequirements,
} from "@/actions/compliances";
import { getThreatScore } from "@/actions/overview";
import {
  ClientAccordionWrapper,
  ComplianceDownloadContainer,
  ComplianceHeader,
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
import { ContentLayout } from "@/components/ui";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import { getReportTypeForFramework } from "@/lib/compliance/compliance-report-types";
import { cn } from "@/lib/utils";
import {
  AttributesData,
  Framework,
  RequirementsTotals,
} from "@/types/compliance";
import { ScanEntity } from "@/types/scans";

interface ComplianceDetailSearchParams {
  complianceId: string;
  version?: string;
  scanId?: string;
  scanData?: string;
  "filter[region__in]"?: string;
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
  const { complianceId, version, scanId, scanData } = resolvedSearchParams;
  const regionFilter = resolvedSearchParams["filter[region__in]"];
  const cisProfileFilter = resolvedSearchParams["filter[cis_profile_level]"];
  const logoPath = getComplianceIcon(compliancetitle);

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

  if (scanData) {
    selectedScan = JSON.parse(decodeURIComponent(scanData));
  }

  const selectedScanId = scanId || selectedScan?.id || null;

  const [metadataInfoData, attributesData] = await Promise.all([
    getComplianceOverviewMetadataInfo({
      filters: {
        "filter[scan_id]": selectedScanId,
      },
    }),
    getComplianceAttributes(complianceId),
  ]);

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
              reportType={getReportTypeForFramework(
                attributesData?.data?.[0]?.attributes?.framework,
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
        />
        {/* <SectionsFailureRateCard categories={categoryHeatmapData} /> */}
      </div>

      <Spacer className="bg-border-neutral-primary h-1 w-full rounded-full" />
      <ClientAccordionWrapper
        hideExpandButton={complianceId.includes("mitre_attack")}
        items={accordionItems}
        defaultExpandedKeys={[]}
      />
    </div>
  );
};
