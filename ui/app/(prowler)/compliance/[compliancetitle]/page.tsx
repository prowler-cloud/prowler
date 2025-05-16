import Image from "next/image";
import { Suspense } from "react";

import { getComplianceDetails } from "@/actions/compliances";
import { getComplianceOverviewMetadataInfo } from "@/actions/compliances";
import { getProvider } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { ComplianceHeader } from "@/components/compliance/compliance-header";
import { FailedSectionsChart } from "@/components/compliance/failed-sections-chart";
import { RequirementsChart } from "@/components/compliance/requirements-chart";
import { SkeletonAccordion } from "@/components/compliance/skeleton-compliance-accordion";
import { ContentLayout } from "@/components/ui";
import { Accordion } from "@/components/ui/accordion/Accordion";
import { mapComplianceData, toAccordionItems } from "@/lib/ens-compliance";
import { ScanProps } from "@/types";

export default async function ComplianceDetail({
  params,
  searchParams,
}: {
  params: { compliancetitle: string };
  searchParams: { id: string; version?: string; scanId?: string };
}) {
  const { compliancetitle } = params;
  const { id, version } = searchParams;

  if (!id) {
    // Todo: improve error handling for no id provided
    throw new Error("No id provided");
  }

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

  if (!scansData?.data) {
    throw new Error("No scans data available");
  }

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

  const selectedScanId =
    searchParams.scanId || expandedScansData[0]?.id || null;

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

      <div className="mb-8 flex justify-start gap-8">
        <div className="relative hidden h-[200px] w-[200px] md:block lg:hidden xl:block">
          <Image
            src="/ens.png"
            alt="ENS Logo"
            fill
            priority
            className="object-contain"
          />
        </div>

        <div className="flex gap-4">
          {/* Requirements Chart */}
          <div className="w-1/2">
            <Suspense
              key={id}
              fallback={
                <div className="bg-muted h-[300px] w-full animate-pulse rounded-lg"></div>
              }
            >
              <SSRRequirementsChart id={id} />
            </Suspense>
          </div>

          {/* Failed Sections List */}
          <div className="w-1/2 min-w-[400px]">
            <Suspense
              key={`failed-sections-${id}`}
              fallback={
                <div className="bg-muted h-[350px] w-full animate-pulse rounded-lg"></div>
              }
            >
              <SSRFailedSectionsChart id={id} />
            </Suspense>
          </div>
        </div>
      </div>

      <Suspense key={id} fallback={<SkeletonAccordion />}>
        <SSRComplianceDetail id={id} scanId={searchParams.scanId} />
      </Suspense>
    </ContentLayout>
  );
}

const getTopFailedSections = (mappedData: any[]) => {
  const failedSectionMap = new Map();

  mappedData.forEach((framework) => {
    framework.categories.forEach((category: any) => {
      category.controls.forEach((control: any) => {
        control.requirements.forEach((requirement: any) => {
          if (requirement.status === "FAIL") {
            const sectionName = category.name;

            if (!failedSectionMap.has(sectionName)) {
              failedSectionMap.set(sectionName, { total: 0, types: {} });
            }

            const sectionData = failedSectionMap.get(sectionName);
            sectionData.total += 1;

            const type = requirement.type;
            sectionData.types[type] = (sectionData.types[type] || 0) + 1;
          }
        });
      });
    });
  });

  // Convert in descending order and slice top 5
  return Array.from(failedSectionMap.entries())
    .map(([name, data]) => ({ name, ...data }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5); // Top 5
};

const SSRFailedSectionsChart = async ({ id }: { id: string }) => {
  const complianceData = await getComplianceDetails(id);
  const mappedData = mapComplianceData(complianceData.data);
  const topFailedSections = getTopFailedSections(mappedData);

  return <FailedSectionsChart sections={topFailedSections} />;
};

const SSRRequirementsChart = async ({ id }: { id: string }) => {
  const complianceData = await getComplianceDetails(id);
  const mappedData = mapComplianceData(complianceData.data);

  const totalRequirements = mappedData.reduce(
    (acc, framework) => ({
      pass: acc.pass + framework.pass,
      fail: acc.fail + framework.fail,
      manual: acc.manual + framework.manual,
    }),
    { pass: 0, fail: 0, manual: 0 },
  );

  return (
    <RequirementsChart
      pass={totalRequirements.pass}
      fail={totalRequirements.fail}
      manual={totalRequirements.manual}
    />
  );
};

const SSRComplianceDetail = async ({
  id,
  scanId,
}: {
  id: string;
  scanId?: string;
}) => {
  const complianceData = await getComplianceDetails(id);

  const mappedData = mapComplianceData(complianceData.data);
  const accordionItems = toAccordionItems(mappedData, scanId);

  return (
    <Accordion
      items={accordionItems}
      variant="light"
      selectionMode="multiple"
      defaultExpandedKeys={[]}
    />
  );
};
