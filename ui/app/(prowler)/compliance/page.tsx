import { Spacer } from "@nextui-org/react";
import { Suspense } from "react";

import { getCompliancesOverview } from "@/actions/compliances";
import { getScans } from "@/actions/scans";
import {
  ComplianceCard,
  ComplianceSkeletonGrid,
} from "@/components/compliance";
import { DataCompliance } from "@/components/compliance/data-compliance";
import { Header } from "@/components/ui";
import { ComplianceOverviewData, SearchParamsProps } from "@/types";

export default async function Compliance({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const scansData = await getScans({});
  const scanList = scansData?.data
    .filter(
      (scan: any) =>
        scan.attributes.state === "completed" &&
        scan.attributes.progress === 100,
    )
    .map((scan: any) => ({
      id: scan.id,
      name: scan.attributes.name || "Unnamed Scan",
      state: scan.attributes.state,
      progress: scan.attributes.progress,
    }));

  const selectedScanId = searchParams.scanId || scanList[0]?.id;

  // Fetch compliance data for regions
  const compliancesData = await getCompliancesOverview({
    scanId: selectedScanId,
  });

  // Extract unique regions
  const regions = compliancesData?.data
    ? Array.from(
        new Set(
          compliancesData.data.map(
            (compliance: ComplianceOverviewData) =>
              compliance.attributes.region as string,
          ),
        ),
      )
    : [];

  return (
    <>
      <Header title="Compliance" icon="fluent-mdl2:compliance-audit" />
      <Spacer y={4} />
      <DataCompliance scans={scanList} regions={regions as string[]} />
      <Spacer y={12} />
      <Suspense fallback={<ComplianceSkeletonGrid />}>
        <SSRComplianceGrid searchParams={searchParams} />
      </Suspense>
    </>
  );
}

const SSRComplianceGrid = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const scanId = searchParams.scanId?.toString() || "";

  const regionFilter = searchParams["filter[region__in]"]?.toString() || "";

  // Fetch compliance data
  const compliancesData = await getCompliancesOverview({
    scanId,
    region: regionFilter,
  });

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
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {compliancesData.data.map((compliance: ComplianceOverviewData) => {
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
