import Image from "next/image";
import { Suspense } from "react";

import { getComplianceDetails } from "@/actions/compliances";
import FailedSectionsList from "@/components/compliance/failed-sections-list";
import { RequirementsChart } from "@/components/compliance/requirements-chart";
import { SkeletonAccordion } from "@/components/compliance/skeleton-compliance-accordion";
import { ContentLayout } from "@/components/ui";
import { Accordion } from "@/components/ui/accordion/Accordion";
import { mapComplianceData, toAccordionItems } from "@/lib/ens-compliance";

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

  return (
    <ContentLayout title={pageTitle} icon="fluent-mdl2:compliance-audit">
      <div className="mb-8 flex gap-4">
        <div className="flex flex-1 gap-4">
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
              <SSRFailedSectionsList id={id} />
            </Suspense>
          </div>
        </div>

        <div className="relative hidden h-[200px] w-[200px] md:block lg:hidden xl:block">
          <Image
            src="/ens.png"
            alt="ENS Logo"
            fill
            priority
            className="object-contain"
          />
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

const SSRFailedSectionsList = async ({ id }: { id: string }) => {
  const complianceData = await getComplianceDetails(id);
  const mappedData = mapComplianceData(complianceData.data);
  const topFailedSections = getTopFailedSections(mappedData);

  return <FailedSectionsList sections={topFailedSections} />;
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
