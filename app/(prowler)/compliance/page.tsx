import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getCompliancesOverview } from "@/actions/compliances";
import { getScans } from "@/actions/scans";
import {
  ComplianceCard,
  ComplianceSkeletonGrid,
} from "@/components/compliance";
import { DataCompliance } from "@/components/compliance/data-compliance";
import { FilterControls } from "@/components/filters";
import { Header } from "@/components/ui";
import { ComplianceOverviewData, SearchParamsProps } from "@/types";

export default async function Compliance({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const scansData = await getScans({});
  const scanList = scansData?.data.map((scan: any) => ({
    id: scan.id,
    name: scan.attributes.name || "Unnamed Scan",
    state: scan.attributes.state,
    progress: scan.attributes.progress,
  }));
  const selectedScanId = searchParams.scanId || scanList[0]?.id;

  return (
    <>
      <Header title="Compliance" icon="fluent-mdl2:compliance-audit" />
      <Spacer y={4} />
      <div className="mb-6">
        <DataCompliance scans={scanList} />
      </div>
      <FilterControls mutedFindings={false} />
      <Spacer y={8} />
      <Suspense fallback={<ComplianceSkeletonGrid />}>
        <SSRComplianceGrid scanId={selectedScanId} />
      </Suspense>
    </>
  );
}

const SSRComplianceGrid = async ({ scanId }: { scanId: string }) => {
  const compliancesData = await getCompliancesOverview({ scanId });

  // Check if the response contains no data
  if (!compliancesData || compliancesData?.data?.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-default-500">
          No compliance data available for the selected scan.
        </div>
      </div>
    );
  }

  // Handle errors returned by the API
  if (compliancesData?.errors?.length > 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-default-500">Provide a valid scan ID.</div>
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
