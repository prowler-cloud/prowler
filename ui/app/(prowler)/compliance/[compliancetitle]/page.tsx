import { Spacer } from "@heroui/spacer";
import Image from "next/image";
import React, { Suspense } from "react";

import {
  getComplianceAttributes,
  getComplianceOverviewMetadataInfo,
  getComplianceRequirements,
} from "@/actions/compliances";
import {
  BarChart,
  BarChartSkeleton,
  ClientAccordionWrapper,
  ComplianceHeader,
  ComplianceScanInfo,
  HeatmapChart,
  HeatmapChartSkeleton,
  PieChart,
  PieChartSkeleton,
  SkeletonAccordion,
} from "@/components/compliance";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { ContentLayout } from "@/components/ui";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import {
  AttributesData,
  Framework,
  RequirementsTotals,
} from "@/types/compliance";
import { ScanEntity } from "@/types/scans";

import { ThreatScoreDownloadButton } from "./threatscore-download-button";

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

const ComplianceIconSmall = ({
  logoPath,
  title,
}: {
  logoPath: string;
  title: string;
}) => {
  return (
    <div className="relative h-6 w-6 shrink-0">
      <Image
        src={logoPath}
        alt={`${title} logo`}
        fill
        className="h-8 w-8 min-w-8 rounded-md border border-gray-300 bg-white object-contain p-[2px]"
      />
    </div>
  );
};

const ComplianceLogo = ({ logoPath }: { logoPath?: string }) => {
  if (!logoPath) {
    return null;
  }

  return (
    <div className="relative h-[200px] w-[200px] rounded-lg border border-gray-300 bg-white p-2 dark:border-gray-700 dark:bg-gray-900">
      <Image
        src={logoPath}
        alt="Compliance logo"
        fill
        className="object-contain p-2"
      />
    </div>
  );
};

const ChartsWrapper = ({
  children,
}: {
  children: React.ReactNode;
  logoPath?: string;
}) => {
  return (
    <div className="mb-8 flex w-full flex-wrap items-center justify-center gap-12 lg:justify-start lg:gap-24">
      {children}
    </div>
  );
};

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
    ? `Compliance Details: ${formattedTitle} - ${version}`
    : `Compliance Details: ${formattedTitle}`;

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
  const finalPageTitle = complianceName
    ? `Compliance Details: ${complianceName}`
    : pageTitle;

  return (
    <ContentLayout
      title={finalPageTitle}
      icon={
        logoPath ? (
          <ComplianceIconSmall logoPath={logoPath} title={compliancetitle} />
        ) : (
          "fluent-mdl2:compliance-audit"
        )
      }
    >
      <div className="relative">
        {logoPath && (
          <div className="absolute top-0 right-0 z-10 hidden sm:block">
            <ComplianceLogo logoPath={logoPath} />
          </div>
        )}
        {selectedScanId && selectedScan && (
          <div className="flex max-w-[328px] flex-col items-start">
            <div className="rounded-lg bg-gray-50 p-2 dark:bg-gray-800">
              <ComplianceScanInfo scan={selectedScan} />
            </div>
            <Spacer y={8} />
          </div>
        )}
        <div className="flex items-center justify-between gap-4">
          <div className="flex-1">
            <ComplianceHeader
              scans={[]}
              uniqueRegions={uniqueRegions}
              showSearch={false}
              framework={compliancetitle}
              showProviders={false}
            />
          </div>
          {attributesData?.data?.[0]?.attributes?.framework ===
            "ProwlerThreatScore" &&
            selectedScanId && (
              <div className="flex-shrink-0">
                <ThreatScoreDownloadButton scanId={selectedScanId} />
              </div>
            )}
        </div>
      </div>

      <Suspense
        key={searchParamsKey}
        fallback={
          <div className="flex flex-col gap-8">
            <ChartsWrapper logoPath={logoPath}>
              <PieChartSkeleton />
              <BarChartSkeleton />
              <HeatmapChartSkeleton />
            </ChartsWrapper>
            <SkeletonAccordion />
          </div>
        }
      >
        <SSRComplianceContent
          complianceId={complianceId}
          scanId={selectedScanId || ""}
          region={regionFilter}
          filter={cisProfileFilter}
          logoPath={logoPath}
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
  logoPath,
  attributesData,
}: {
  complianceId: string;
  scanId: string;
  region?: string;
  filter?: string;
  logoPath?: string;
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
        <ChartsWrapper logoPath={logoPath}>
          <PieChart pass={0} fail={0} manual={0} />
          <BarChart sections={[]} />
          <HeatmapChart categories={[]} />
        </ChartsWrapper>
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
  const categoryHeatmapData = mapper.calculateCategoryHeatmapData(data);
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
      <ChartsWrapper logoPath={logoPath}>
        <PieChart
          pass={totalRequirements.pass}
          fail={totalRequirements.fail}
          manual={totalRequirements.manual}
        />
        <BarChart sections={topFailedSections} />
        <HeatmapChart categories={categoryHeatmapData} />
      </ChartsWrapper>

      <Spacer className="h-1 w-full rounded-full bg-gray-200 dark:bg-gray-800" />
      <ClientAccordionWrapper
        hideExpandButton={complianceId.includes("mitre_attack")}
        items={accordionItems}
        defaultExpandedKeys={[]}
      />
    </div>
  );
};
