import { Spacer } from "@heroui/spacer";
import { Suspense } from "react";

import {
  getComplianceAttributes,
  getComplianceOverviewMetadataInfo,
  getComplianceRequirements,
} from "@/actions/compliances";
import {
  ClientAccordionWrapper,
  ComplianceDownloadButton,
  ComplianceHeader,
  RequirementsStatusCard,
  RequirementsStatusCardSkeleton,
  // SectionsFailureRateCard,
  // SectionsFailureRateCardSkeleton,
  SkeletonAccordion,
  TopFailedSectionsCard,
  TopFailedSectionsCardSkeleton,
} from "@/components/compliance";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { ContentLayout } from "@/components/ui";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import { getReportTypeForFramework } from "@/lib/compliance/compliance-report-types";
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

  // Use compliance_name from attributes if available, otherwise fallback to formatted title
  const complianceName = attributesData?.data?.[0]?.attributes?.compliance_name;
  const finalPageTitle = complianceName ? `${complianceName}` : pageTitle;

  return (
    <ContentLayout title={finalPageTitle}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
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
        {(() => {
          const framework = attributesData?.data?.[0]?.attributes?.framework;
          const reportType = getReportTypeForFramework(framework);

          return selectedScanId && reportType ? (
            <div className="flex-shrink-0 pt-1">
              <ComplianceDownloadButton
                scanId={selectedScanId}
                reportType={reportType}
              />
            </div>
          ) : null;
        })()}
      </div>

      <Suspense
        key={searchParamsKey}
        fallback={
          <div className="flex flex-col gap-8">
            <div className="flex flex-col gap-6 md:flex-row md:flex-wrap md:items-stretch">
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
}: {
  complianceId: string;
  scanId: string;
  region?: string;
  filter?: string;
  attributesData: AttributesData;
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
        <div className="flex flex-col gap-6 md:flex-row md:flex-wrap md:items-stretch">
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
  const topFailedSections = mapper.getTopFailedSections(data);

  return (
    <div className="flex flex-col gap-8">
      <div className="flex flex-col gap-6 md:flex-row md:items-stretch">
        <RequirementsStatusCard
          pass={totalRequirements.pass}
          fail={totalRequirements.fail}
          manual={totalRequirements.manual}
        />
        <TopFailedSectionsCard sections={topFailedSections} />
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
