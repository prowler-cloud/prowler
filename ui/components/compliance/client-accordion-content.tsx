"use client";

import { useEffect, useState } from "react";

import { getFindings } from "@/actions/findings/findings";
import { ColumnFindings } from "@/components/findings/table";
import { Accordion } from "@/components/ui/accordion/Accordion";
import { DataTable, StatusFindingBadge } from "@/components/ui/table";
import { createDict } from "@/lib";
import { FindingProps } from "@/types/components";

interface ClientAccordionContentProps {
  requirement: any;
  scanId: string;
}

export function ClientAccordionContent({
  requirement,
  scanId,
}: ClientAccordionContentProps) {
  const [findings, setFindings] = useState<any>(null);
  const [expandedFindings, setExpandedFindings] = useState<FindingProps[]>([]);
  const [isExpanded, setIsExpanded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // When the component is mounted (which means it is expanded)
  useEffect(() => {
    async function loadFindings() {
      if (!isExpanded && requirement.checks && requirement.checks.length > 0) {
        setIsExpanded(true);
        setIsLoading(true);

        const checkIds = requirement.checks.map(
          (check: any) => check.checkName,
        );

        const findingsData = await getFindings({
          filters: {
            "filter[check_id__in]": checkIds.join(","),
            "filter[scan]": scanId,
          },
        });

        console.log("FINDINGS", findingsData);

        setFindings(findingsData);

        if (findingsData?.data) {
          // Create dictionaries for resources, scans, and providers
          const resourceDict = createDict("resources", findingsData);
          const scanDict = createDict("scans", findingsData);
          const providerDict = createDict("providers", findingsData);

          // Expand each finding with its corresponding resource, scan, and provider
          const expandedData = findingsData.data.map(
            (finding: FindingProps) => {
              const scan = scanDict[finding.relationships?.scan?.data?.id];
              const resource =
                resourceDict[finding.relationships?.resources?.data?.[0]?.id];
              const provider =
                providerDict[scan?.relationships?.provider?.data?.id];

              return {
                ...finding,
                relationships: { scan, resource, provider },
              };
            },
          );

          setExpandedFindings(expandedData);
        }

        setIsLoading(false);
      }
    }

    loadFindings();
  }, [requirement, scanId, isExpanded]);

  // Reuse the renderTable logic but now with dynamically loaded findings

  const checks = requirement.checks || [];

  // Prepare the checks table as content for the accordion
  const checksTable = (
    <div className="overflow-x-auto">
      {checks.map((check: any, i: number) => (
        <div key={i} className="flex items-center justify-between">
          <span>{check.checkName}</span>
          <StatusFindingBadge status={check.status} />
        </div>
      ))}
    </div>
  );

  // Create a single accordion item for the checks
  const accordionItems = [
    {
      key: "checks",
      title: (
        <div className="flex items-center gap-2">
          <span className="text-primary">{checks.length}</span>
          <span>Checks</span>
        </div>
      ),
      content: checksTable,
    },
  ];

  return (
    <div className="w-full overflow-x-auto">
      <div className="mb-4 text-sm text-gray-600">
        {requirement.description}
      </div>

      {checks.length > 0 && (
        <div className="mb-6 mt-2">
          <Accordion
            items={accordionItems}
            variant="bordered"
            defaultExpandedKeys={["checks"]}
            className="rounded-lg bg-white shadow-sm dark:bg-prowler-blue-400"
          />
        </div>
      )}

      {!isLoading && findings && findings.data && findings.data.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-2 font-medium">Findings</h3>
          <div className="overflow-x-auto p-1">
            <DataTable
              columns={ColumnFindings}
              data={expandedFindings || []}
              metadata={findings?.meta}
            />
          </div>
        </div>
      )}
    </div>
  );
}
