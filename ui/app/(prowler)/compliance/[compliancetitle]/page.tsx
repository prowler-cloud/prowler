import { Spacer } from "@nextui-org/react";
import Image from "next/image";
import { Suspense } from "react";

import {
  getComplianceAttributes,
  getComplianceOverviewMetadataInfo,
  getComplianceRequirements,
} from "@/actions/compliances";
import { getProvider } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { ClientAccordionWrapper } from "@/components/compliance/compliance-accordion/client-accordion-wrapper";
import { ComplianceHeader } from "@/components/compliance/compliance-header/compliance-header";
import { SkeletonAccordion } from "@/components/compliance/compliance-skeleton-accordion";
import { FailedSectionsChart } from "@/components/compliance/failed-sections-chart";
import { FailedSectionsChartSkeleton } from "@/components/compliance/failed-sections-chart-skeleton";
import { RequirementsChart } from "@/components/compliance/requirements-chart";
import { RequirementsChartSkeleton } from "@/components/compliance/requirements-chart-skeleton";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { ContentLayout } from "@/components/ui";
import { getComplianceMapper } from "@/lib/compliance/commons";
import { ScanProps } from "@/types";
import { Framework, RequirementsTotals } from "@/types/compliance";

interface ComplianceDetailSearchParams {
  complianceId: string;
  version?: string;
  scanId?: string;
  "filter[region__in]"?: string;
}

const ComplianceLogo = ({ logoPath }: { logoPath: string }) => {
  return (
    <div className="relative ml-auto hidden h-[200px] w-[200px] flex-shrink-0 md:block">
      <Image
        src={logoPath}
        alt="Compliance Logo"
        fill
        priority
        className="object-contain"
      />
    </div>
  );
};

const ChartsWrapper = ({
  children,
  logoPath,
}: {
  children: React.ReactNode;
  logoPath?: string;
}) => {
  return (
    <div className="mb-8 flex w-full">
      <div className="flex flex-col items-center gap-16 lg:flex-row">
        {children}
      </div>
      {logoPath && <ComplianceLogo logoPath={logoPath} />}
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
  const expandedScansData = await Promise.all(
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
  );

  const selectedScanId = scanId || expandedScansData[0]?.id || null;

  // Fetch metadata info for regions
  const metadataInfoData = await getComplianceOverviewMetadataInfo({
    filters: {
      "filter[scan_id]": selectedScanId,
    },
  });

  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];

  return (
    <ContentLayout title={pageTitle} icon="fluent-mdl2:compliance-audit">
      <ComplianceHeader
        scans={expandedScansData}
        uniqueRegions={uniqueRegions}
        showSearch={false}
      />

      <Suspense
        key={searchParamsKey}
        fallback={
          <div className="space-y-8">
            <ChartsWrapper logoPath={logoPath}>
              <RequirementsChartSkeleton />
              <FailedSectionsChartSkeleton />
            </ChartsWrapper>
            <SkeletonAccordion />
          </div>
        }
      >
        <SSRComplianceContent
          complianceId={complianceId}
          scanId={selectedScanId}
          region={regionFilter}
          logoPath={logoPath}
        />
      </Suspense>
    </ContentLayout>
  );
}

const getComplianceData = async (
  complianceId: string,
  scanId: string,
  region?: string,
): Promise<Framework[]> => {
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

  // Get the appropriate mapper for this framework
  const mapper = getComplianceMapper(framework);
  const mappedData = mapper.mapComplianceData(attributesData, requirementsData);

  return mappedData;
};

const SSRComplianceContent = async ({
  complianceId,
  scanId,
  region,
  logoPath,
}: {
  complianceId: string;
  scanId: string;
  region?: string;
  logoPath?: string;
}) => {
  if (!scanId) {
    return (
      <div className="space-y-8">
        <ChartsWrapper logoPath={logoPath}>
          <RequirementsChart pass={0} fail={0} manual={0} />
          <FailedSectionsChart sections={[]} />
        </ChartsWrapper>
        <ClientAccordionWrapper items={[]} defaultExpandedKeys={[]} />
      </div>
    );
  }

  const data = await getComplianceData(complianceId, scanId, region);
  const totalRequirements: RequirementsTotals = data.reduce(
    (acc, framework) => ({
      pass: acc.pass + framework.pass,
      fail: acc.fail + framework.fail,
      manual: acc.manual + framework.manual,
    }),
    { pass: 0, fail: 0, manual: 0 },
  );

  // Get the framework to determine which mapper to use
  const attributesData = await getComplianceAttributes(complianceId);
  const framework = attributesData?.data?.[0]?.attributes?.framework;

  // Get the appropriate mapper for this framework
  const mapper = getComplianceMapper(framework);
  const accordionItems = mapper.toAccordionItems(data, scanId);
  const topFailedSections = mapper.getTopFailedSections(data);

  // Todo: rethink as every compliance has a different number of items
  // const defaultKeys = accordionItems.slice(0, 2).map((item) => item.key);
  const defaultKeys = [""];

  return (
    <div className="space-y-8">
      <ChartsWrapper logoPath={logoPath}>
        <RequirementsChart
          pass={totalRequirements.pass}
          fail={totalRequirements.fail}
          manual={totalRequirements.manual}
        />
        <FailedSectionsChart sections={topFailedSections} />
      </ChartsWrapper>

      <Spacer className="h-1 w-full rounded-full bg-gray-200 dark:bg-gray-800" />
      <ClientAccordionWrapper
        items={accordionItems}
        defaultExpandedKeys={defaultKeys}
      />
    </div>
  );
};
