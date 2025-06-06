import { Spacer } from "@nextui-org/react";
import Image from "next/image";
import React, { Suspense } from "react";

import {
  getComplianceAttributes,
  getComplianceOverviewMetadataInfo,
  getComplianceRequirements,
} from "@/actions/compliances";
import { getProvider } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import {
  BarChart,
  BarChartSkeleton,
  ClientAccordionWrapper,
  ComplianceHeader,
  HeatmapChart,
  HeatmapChartSkeleton,
  PieChart,
  PieChartSkeleton,
  SkeletonAccordion,
} from "@/components/compliance";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { ContentLayout } from "@/components/ui";
import {
  calculateCategoryHeatmapData,
  getComplianceMapper,
} from "@/lib/compliance/commons";
import { ScanProps } from "@/types";
import { Framework, RequirementsTotals } from "@/types/compliance";

interface ComplianceDetailSearchParams {
  complianceId: string;
  version?: string;
  scanId?: string;
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
        className="h-10 w-10 min-w-10 rounded-md border-1 border-gray-300 bg-white object-contain p-[2px]"
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
    <div className="mb-8 flex w-full flex-wrap items-center justify-center gap-12 lg:justify-start">
      {children &&
        React.Children.toArray(children).map(
          (child: React.ReactNode, index: number) => (
            <div
              key={index}
              className="rounded-lg bg-gray-50 p-6 dark:bg-gray-900"
            >
              {child}
            </div>
          ),
        )}
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
  const { complianceId, version, scanId } = searchParams;
  const regionFilter = searchParams["filter[region__in]"];
  const cisProfileFilter = searchParams["filter[cis_profile_level]"];
  const logoPath = getComplianceIcon(compliancetitle);

  // Create a key that includes region filter for Suspense
  const searchParamsKey = JSON.stringify(searchParams || {});

  const formattedTitle = compliancetitle.split("-").join(" ");
  const pageTitle = version
    ? `Compliance Details: ${formattedTitle} - ${version}`
    : `Compliance Details: ${formattedTitle}`;

  // Fetch scans data
  const scansData = await getScans({
    filters: {
      "filter[state]": "completed",
    },
  });

  // Expand scans with provider information
  const expandedScansData = scansData?.data?.length
    ? await Promise.all(
        scansData.data.map(async (scan: ScanProps) => {
          const providerId = scan.relationships?.provider?.data?.id;

          if (!providerId) {
            return { ...scan, providerInfo: null };
          }

          const formData = new FormData();
          formData.append("id", providerId);

          const providerData = await getProvider(formData);

          return {
            ...scan,
            providerInfo: providerData?.data
              ? {
                  provider: providerData.data.attributes.provider,
                  uid: providerData.data.attributes.uid,
                  alias: providerData.data.attributes.alias,
                }
              : null,
          };
        }),
      )
    : [];

  const selectedScanId = scanId || expandedScansData[0]?.id || null;

  // Fetch metadata info for regions
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
      <ComplianceHeader
        scans={expandedScansData}
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
          scanId={selectedScanId}
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
  if (!scanId) {
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

  // Get compliance data and attributes once
  const [attributesData, requirementsData] = await Promise.all([
    getComplianceAttributes(complianceId),
    getComplianceRequirements({
      complianceId,
      scanId,
      region,
    }),
  ]);

  // Determine framework from the first attribute item
  const framework = attributesData?.data?.[0]?.attributes?.framework;
  const mapper = getComplianceMapper(framework);

  // Use the same data for both compliance view and heatmap
  const data = mapper.mapComplianceData(
    attributesData,
    requirementsData,
    filter,
  );

  // Calculate category heatmap data
  const categoryHeatmapData = calculateCategoryHeatmapData(data);

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

  // Todo: rethink as every compliance has a different number of items
  // const defaultKeys = accordionItems.slice(0, 2).map((item) => item.key);
  const defaultKeys = [""];

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
        items={accordionItems}
        defaultExpandedKeys={defaultKeys}
      />
    </div>
  );
};
