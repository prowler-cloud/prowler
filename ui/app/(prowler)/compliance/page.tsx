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
  let scansData;
  let scanList: {
    id: string;
    name: string;
    state: string;
    progress: number;
  }[] = [];

  try {
    scansData = await getScans({});
    scanList =
      scansData?.data
        ?.filter(
          (scan: any) =>
            scan.attributes.state === "completed" &&
            scan.attributes.progress === 100,
        )
        .map((scan: any) => ({
          id: scan.id,
          name: scan.attributes.name || "Unnamed Scan",
          state: scan.attributes.state,
          progress: scan.attributes.progress,
        })) || [];
  } catch (error) {
    console.error("Error fetching scans data:", error);
  }

  const selectedScanId = searchParams.scanId || scanList[0]?.id || null;

  // If there are no scans available, return a message
  if (!selectedScanId) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-default-500">No scans available to select.</div>
      </div>
    );
  }

  // Fetch compliance data for regions
  let compliancesData;
  let regions: string[] = [];
  try {
    compliancesData = await getCompliancesOverview({
      scanId: selectedScanId as string,
    });
    regions = compliancesData?.data
      ? Array.from(
          new Set(
            compliancesData.data.map(
              (compliance: ComplianceOverviewData) =>
                compliance.attributes.region as string,
            ),
          ),
        )
      : [];
  } catch (error) {
    console.error("Error fetching compliance data:", error);
  }

  return (
    <>
      <Header title="Compliance" icon="fluent-mdl2:compliance-audit" />
      <Spacer y={4} />
      <DataCompliance scans={scanList} regions={regions} />
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
  let compliancesData;
  try {
    compliancesData = await getCompliancesOverview({
      scanId,
      region: regionFilter,
    });
  } catch (error) {
    console.error("Error fetching compliances overview:", error);
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-default-500">
          Failed to load compliance data. Please try again later.
        </div>
      </div>
    );
  }

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
          version,
          requirements_status: { passed, total },
        } = attributes;

        return (
          <ComplianceCard
            key={compliance.id}
            title={framework}
            version={version}
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
