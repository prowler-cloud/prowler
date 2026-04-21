"use client";

import { useState } from "react";

import { ComplianceCard } from "@/components/compliance/compliance-card";
import { DataTableSearch } from "@/components/ui/table/data-table-search";
import type { ComplianceOverviewData } from "@/types/compliance";
import type { ScanEntity } from "@/types/scans";

interface ComplianceOverviewGridProps {
  frameworks: ComplianceOverviewData[];
  scanId: string;
  selectedScan?: ScanEntity;
  /**
   * Subset of compliance_ids that represent the latest CIS variant per
   * provider. Only those cards should expose a PDF download button, matching
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
  const [searchTerm, setSearchTerm] = useState("");

  const filteredFrameworks = frameworks.filter((compliance) =>
    compliance.attributes.framework
      .toLowerCase()
      .includes(searchTerm.toLowerCase()),
  );

  return (
    <>
      <div className="flex items-center justify-between gap-4">
        <DataTableSearch
          controlledValue={searchTerm}
          onSearchChange={setSearchTerm}
          placeholder="Search frameworks..."
        />
        <span className="text-text-neutral-secondary shrink-0 text-sm">
          {filteredFrameworks.length.toLocaleString()} Total Entries
        </span>
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
        {filteredFrameworks.map((compliance) => {
          const { attributes, id } = compliance;
          const {
            framework,
            version,
            requirements_passed,
            total_requirements,
          } = attributes;

          return (
            <ComplianceCard
              key={id}
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
        })}
      </div>
    </>
  );
};
