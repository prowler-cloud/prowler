import { Suspense } from "react";

import { getComplianceDetails } from "@/actions/compliances";
import { SkeletonAccordion } from "@/components/compliance/skeleton-compliance-accordion";
import { ContentLayout } from "@/components/ui";
import { Accordion } from "@/components/ui/accordion/Accordion";
import { mapComplianceData, toAccordionItems } from "@/lib/ens-compliance";

export default async function ComplianceDetail({
  params,
  searchParams,
}: {
  params: { compliancetitle: string };
  searchParams: { id: string; version?: string };
}) {
  const { compliancetitle } = params;
  const { id, version } = searchParams;

  if (!id) {
    // Todo: improve error handling for no id provided
    throw new Error("No id provided");
  }

  const complianceData = await getComplianceDetails(id);

  const formattedTitle = compliancetitle.split("-").join(" ");

  const pageTitle = version
    ? `Detalles de Compliance: ${formattedTitle} - ${version}`
    : `Detalles de Compliance: ${formattedTitle}`;

  const mappedData = mapComplianceData(complianceData.data);
  const accordionItems = toAccordionItems(mappedData);

  return (
    <ContentLayout title={pageTitle} icon="fluent-mdl2:compliance-audit">
      <Suspense key={id} fallback={<SkeletonAccordion />}>
        <Accordion
          items={accordionItems}
          variant="bordered"
          selectionMode="multiple"
          defaultExpandedKeys={[]}
        />
      </Suspense>
    </ContentLayout>
  );
}
