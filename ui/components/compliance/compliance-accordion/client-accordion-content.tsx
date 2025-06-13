"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { getFindings } from "@/actions/findings/findings";
import {
  ColumnFindings,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { Accordion } from "@/components/ui/accordion/Accordion";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import { Requirement } from "@/types/compliance";
import { FindingProps, FindingsResponse } from "@/types/components";

interface ClientAccordionContentProps {
  requirement: Requirement;
  scanId: string;
  framework: string;
  disableFindings?: boolean;
}

export const ClientAccordionContent = ({
  requirement,
  framework,
  scanId,
  disableFindings = false,
}: ClientAccordionContentProps) => {
  const [findings, setFindings] = useState<FindingsResponse | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<FindingProps[]>([]);
  const searchParams = useSearchParams();
  const pageNumber = searchParams.get("page") || "1";
  const complianceId = searchParams.get("complianceId");
  const defaultSort = "severity,status,-inserted_at";
  const sort = searchParams.get("sort") || defaultSort;
  const loadedPageRef = useRef<string | null>(null);
  const loadedSortRef = useRef<string | null>(null);
  const isExpandedRef = useRef(false);
  const region = searchParams.get("filter[region__in]") || "";

  useEffect(() => {
    async function loadFindings() {
      if (
        !disableFindings &&
        requirement.check_ids?.length > 0 &&
        requirement.status !== "No findings" &&
        (loadedPageRef.current !== pageNumber ||
          loadedSortRef.current !== sort ||
          !isExpandedRef.current)
      ) {
        loadedPageRef.current = pageNumber;
        loadedSortRef.current = sort;
        isExpandedRef.current = true;

        try {
          const checkIds = requirement.check_ids;
          const encodedSort = sort.replace(/^\+/, "");
          const findingsData = await getFindings({
            filters: {
              "filter[check_id__in]": checkIds.join(","),
              "filter[scan]": scanId,
              ...(region && { "filter[region__in]": region }),
            },
            page: parseInt(pageNumber, 10),
            sort: encodedSort,
          });

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
        } catch (error) {
          console.error("Error loading findings:", error);
        }
      }
    }

    loadFindings();
  }, [requirement, scanId, pageNumber, sort, region, disableFindings]);

  const renderDetails = () => {
    if (!complianceId) {
      return null;
    }

    const mapper = getComplianceMapper(framework);
    const detailsComponent = mapper.getDetailsComponent(requirement);

    return <div className="w-full">{detailsComponent}</div>;
  };

  if (disableFindings) {
    return (
      <div className="w-full">
        {renderDetails()}
        <p className="mb-1 mt-3 text-sm font-medium text-gray-800 dark:text-gray-200">
          ⚠️ This requirement has no checks; therefore, there are no findings.
        </p>
      </div>
    );
  }

  const checks = requirement.check_ids || [];
  const checksList = (
    <div className="flex items-center px-2 text-sm">
      <div className="w-full flex-col">
        <div className="mb-1 mt-[-8px] h-1 w-full border-b border-gray-200 dark:border-gray-800" />
        <span className="text-gray-600 dark:text-gray-200" aria-label="Checks">
          {checks.join(", ")}
        </span>
      </div>
    </div>
  );

  const accordionChecksItems = [
    {
      key: "checks",
      title: (
        <div className="flex items-center gap-2">
          <span className="text-primary">{checks.length}</span>
          {checks.length > 1 ? <span>Checks</span> : <span>Check</span>}
        </div>
      ),
      content: checksList,
    },
  ];

  const renderFindingsTable = () => {
    if (findings === null && requirement.status !== "MANUAL") {
      return <SkeletonTableFindings />;
    }

    if (findings?.data?.length && findings.data.length > 0) {
      return (
        <>
          <h4 className="mb-2 text-sm font-medium">Findings</h4>

          <DataTable
            // Remove the updated_at column as compliance is for the last scan
            columns={ColumnFindings.filter(
              (_, index) => index !== 4 && index !== 7,
            )}
            data={expandedFindings || []}
            metadata={findings?.meta}
            disableScroll={true}
          />
        </>
      );
    }

    return (
      <div className="mb-1 mt-3 text-sm font-medium text-gray-800 dark:text-gray-200">
        ⚠️ There are no findings for these regions
      </div>
    );
  };

  return (
    <div className="w-full">
      {renderDetails()}

      {checks.length > 0 && (
        <div className="my-4">
          <Accordion
            items={accordionChecksItems}
            variant="light"
            defaultExpandedKeys={[""]}
            className="rounded-lg bg-gray-50 dark:bg-prowler-blue-400"
          />
        </div>
      )}

      {renderFindingsTable()}
    </div>
  );
};
