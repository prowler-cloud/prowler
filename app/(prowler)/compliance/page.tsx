import { Spacer } from "@nextui-org/react";
import { redirect } from "next/navigation";
import { Suspense } from "react";

import { getCompliance } from "@/actions/compliance";
import {
  ComplianceCard,
  ComplianceSkeletonGrid,
} from "@/components/compliance";
import { FilterControls } from "@/components/filters";
import { Header } from "@/components/ui";
import { searchParamsProps } from "@/types";

export default async function Compliance({ searchParams }: searchParamsProps) {
  return (
    <>
      <Header title="Compliance" icon="fluent-mdl2:compliance-audit" />
      <Spacer y={4} />
      <FilterControls mutedFindings={false} />
      <Spacer y={4} />
      <Suspense key={searchParams.page} fallback={<ComplianceSkeletonGrid />}>
        <SSRComplianceGrid searchParams={searchParams} />
      </Suspense>
    </>
  );
}

const SSRComplianceGrid = async ({ searchParams }: searchParamsProps) => {
  const page = searchParams.page ? parseInt(searchParams.page) : 1;
  const compliancesData = await getCompliance({ page });
  const [compliances] = await Promise.all([compliancesData]);

  if (compliances?.errors) redirect("/compliance");

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 3xl:grid-cols-4">
      {compliances.compliance?.data.map((compliance: any) => (
        <ComplianceCard
          key={compliance.id}
          title={compliance.attributes.title}
          passingRequirements={compliance.attributes.passingRequirements}
          totalRequirements={compliance.attributes.totalRequirements}
          prevPassingRequirements={
            compliance.lastScan.attributes.passingRequirements
          }
          prevTotalRequirements={
            compliance.lastScan.attributes.totalRequirements
          }
        />
      ))}
    </div>
  );
};
