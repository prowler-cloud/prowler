"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { ComplianceCard } from "@/components/compliance/compliance-card";
import { OnboardingTrigger, PageReady } from "@/components/onboarding";
import { DataTableSearch } from "@/components/ui/table/data-table-search";
import { buildComplianceDetailPath } from "@/lib/compliance/compliance-detail-url";
import { getFlowById } from "@/lib/onboarding";
import { createViewComplianceTourStepHandlers } from "@/lib/tours/view-compliance.tour";
import type { ComplianceOverviewData } from "@/types/compliance";
import type { ScanEntity } from "@/types/scans";

const viewComplianceFlow = getFlowById("view-compliance")!;

// Module-level so the identity is stable: `configOverrides` is an effect dependency in
// `useDriverTour`, and a fresh object per keystroke would tear the tour down mid-typing.
const VIEW_COMPLIANCE_TOUR_CONFIG = {
  // Last step opens the first card (see createViewComplianceTourStepHandlers).
  doneBtnText: "Open Compliance",
};

interface ComplianceOverviewGridProps {
  frameworks: ComplianceOverviewData[];
  scanId: string;
  selectedScan?: ScanEntity;
  /**
   * Subset of compliance_ids that represent the latest CIS variant per
   * provider. Only those cards expose the PDF download button, matching
   * the backend's latest-only CIS PDF generation.
   */
  latestCisIds?: ReadonlySet<string>;
}

export const ComplianceOverviewGrid = ({
  frameworks,
  scanId,
  selectedScan,
  latestCisIds,
}: ComplianceOverviewGridProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [searchTerm, setSearchTerm] = useState("");

  const filteredFrameworks = frameworks.filter((compliance) =>
    compliance.attributes.framework
      .toLowerCase()
      .includes(searchTerm.toLowerCase()),
  );

  const resetSearch = () => {
    setSearchTerm("");
    return frameworks.length > 0;
  };

  const openFirstFramework = () => {
    const first = frameworks[0];
    if (!first) return;
    router.push(
      buildComplianceDetailPath({
        title: first.attributes.framework,
        complianceId: first.id,
        version: first.attributes.version,
        scanId,
        regionFilter: searchParams.get("filter[region__in]"),
      }),
    );
  };

  return (
    <>
      {/* Suspense required: OnboardingTrigger reads useSearchParams */}
      <Suspense fallback={null}>
        <OnboardingTrigger
          flow={viewComplianceFlow}
          stepHandlers={createViewComplianceTourStepHandlers({
            resetSearch,
            openFirstFramework,
          })}
          configOverrides={VIEW_COMPLIANCE_TOUR_CONFIG}
        />
      </Suspense>
      {/* Signals the navbar that this route's data has loaded (enables the replay icon). */}
      <PageReady />
      <div className="flex items-center justify-between gap-4">
        <div data-tour-id="view-compliance-search">
          <DataTableSearch
            controlledValue={searchTerm}
            onSearchChange={setSearchTerm}
            placeholder="Search frameworks..."
          />
        </div>
        <span className="text-text-neutral-secondary shrink-0 text-sm">
          {filteredFrameworks.length.toLocaleString()} Total Entries
        </span>
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
        {filteredFrameworks.map((compliance, index) => {
          const { attributes, id } = compliance;
          const {
            framework,
            version,
            requirements_passed,
            total_requirements,
          } = attributes;

          const card = (
            <ComplianceCard
              title={framework}
              version={version}
              passingRequirements={requirements_passed}
              totalRequirements={total_requirements}
              prevPassingRequirements={requirements_passed}
              prevTotalRequirements={total_requirements}
              scanId={scanId}
              complianceId={id}
              id={id}
              selectedScan={selectedScan}
              isLatestCisForProvider={latestCisIds?.has(id) ?? false}
            />
          );

          // Anchor the tour to a single card, not the whole grid: highlighting the
          // grid lit up the entire viewport and scrolled the page to the bottom.
          return index === 0 ? (
            <div
              key={id}
              data-tour-id="view-compliance-frameworks"
              className="h-full [&>*]:h-full"
            >
              {card}
            </div>
          ) : (
            <div key={id} className="h-full [&>*]:h-full">
              {card}
            </div>
          );
        })}
      </div>
    </>
  );
};
