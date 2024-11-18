import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getCompliancesOverview } from "@/actions/compliances";
import {
  ComplianceCard,
  ComplianceSkeletonGrid,
} from "@/components/compliance";
import { FilterControls } from "@/components/filters";
import { Header } from "@/components/ui";
import { ComplianceOverviewData, SearchParamsProps } from "@/types";

export default async function Compliance({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const searchParamsKey = JSON.stringify(searchParams || {});

  return (
    <>
      <Header title="Compliance" icon="fluent-mdl2:compliance-audit" />
      <Spacer y={4} />
      <FilterControls mutedFindings={false} />
      <Spacer y={8} />
      <Suspense key={searchParamsKey} fallback={<ComplianceSkeletonGrid />}>
        <SSRComplianceGrid />
      </Suspense>
    </>
  );
}

const SSRComplianceGrid = async () => {
  // const scanId = "01929f57-c0ee-7553-be0b-cbde006fb6f7";
  const scanId = "0193358c-bd7f-7eec-b13a-2d4a648b8df";
  const compliancesData = await getCompliancesOverview({ scanId });
  console.log(compliancesData, "compliancesData");

  if (compliancesData?.errors?.length > 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-default-500">There is no compliance data.</div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {compliancesData?.data?.map((compliance: ComplianceOverviewData) => {
        const { attributes } = compliance;
        const {
          framework,
          requirements_status: { passed, total },
        } = attributes;

        return (
          <ComplianceCard
            key={compliance.id}
            title={framework}
            passingRequirements={passed}
            totalRequirements={total}
            prevPassingRequirements={passed}
            prevTotalRequirements={total}
          />
        );
      })}
    </div>
  );
};
