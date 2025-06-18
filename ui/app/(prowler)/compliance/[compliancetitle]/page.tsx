import { Spacer } from "@nextui-org/react";
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
import { Framework, RequirementsTotals } from "@/types/compliance";
import { ScanEntity } from "@/types/scans";

interface ComplianceDetailSearchParams {
  complianceId: string;
  version?: string;
  scanId?: string;
  scanData?: string;
  "filter[region__in]"?: string;
  "filter[cis_profile_level]"?: string;
}

const ComplianceIconSmall = ({
  logoPath,
  title,
}: {
  logoPath: string;
  title: string;
}) => {
  return (
    <div className="relative h-6 w-6 flex-shrink-0">
      <Image
        src={logoPath}
        alt={`${title} logo`}
        fill
        className="h-8 w-8 min-w-8 rounded-md border-1 border-gray-300 bg-white object-contain p-[2px]"
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
  params: { compliancetitle: string };
  searchParams: ComplianceDetailSearchParams;
}) {
  const { compliancetitle } = params;
  const { complianceId, version, scanId, scanData } = searchParams;
  const regionFilter = searchParams["filter[region__in]"];
  const cisProfileFilter = searchParams["filter[cis_profile_level]"];
  const logoPath = getComplianceIcon(compliancetitle);

  // Create a key that includes region filter for Suspense
  const searchParamsKey = JSON.stringify(searchParams || {});

  const formattedTitle = compliancetitle.split("-").join(" ");
  const pageTitle = version
    ? `Compliance Details: ${formattedTitle} - ${version}`
    : `Compliance Details: ${formattedTitle}`;

  let selectedScan: ScanEntity | null = null;

  if (scanData) {
    selectedScan = JSON.parse(decodeURIComponent(scanData));
  }

  const selectedScanId = scanId || selectedScan?.id || null;

  const metadataInfoData = await getComplianceOverviewMetadataInfo({
    filters: {
      "filter[scan_id]": selectedScanId,
    },
  });
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];

  return (
    <ContentLayout
      title={pageTitle}
      icon={
        logoPath ? (
          <ComplianceIconSmall logoPath={logoPath} title={compliancetitle} />
        ) : (
          "fluent-mdl2:compliance-audit"
        )
      }
    >
      {selectedScanId && selectedScan && (
        <div className="flex max-w-[328px] flex-col items-start">
          <ComplianceScanInfo scan={selectedScan} />
          <Spacer y={8} />
        </div>
      )}
      <ComplianceHeader
        scans={[]}
        uniqueRegions={uniqueRegions}
        showSearch={false}
        framework={compliancetitle}
        showProviders={false}
      />

      <Suspense
        key={searchParamsKey}
        fallback={
          <div className="space-y-8">
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
}: {
  complianceId: string;
  scanId: string;
  region?: string;
  filter?: string;
  logoPath?: string;
}) => {
  const [attributesData, requirementsData] = await Promise.all([
    getComplianceAttributes(complianceId),
    getComplianceRequirements({
      complianceId,
      scanId,
      region,
    }),
  ]);
  const type = requirementsData?.data?.[0]?.type;

  if (!scanId || type === "tasks") {
    return (
      <div className="space-y-8">
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
    <div className="space-y-8">
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
