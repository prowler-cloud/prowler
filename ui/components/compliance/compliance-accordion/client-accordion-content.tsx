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
import { ComplianceId, Requirement } from "@/types/compliance";
import { FindingProps, FindingsResponse } from "@/types/components";

import { ENSCustomDetails } from "../compliance-custom-details/ens-details";
import { ISOCustomDetails } from "../compliance-custom-details/iso-details";

interface ClientAccordionContentProps {
  requirement: Requirement;
  scanId: string;
}

export const ClientAccordionContent = ({
  requirement,
  scanId,
}: ClientAccordionContentProps) => {
  const [findings, setFindings] = useState<FindingsResponse | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<FindingProps[]>([]);
  const searchParams = useSearchParams();
  const pageNumber = searchParams.get("page") || "1";
  const complianceId = searchParams.get("complianceId") as ComplianceId;
  const defaultSort = "severity,status,-inserted_at";
  const sort = searchParams.get("sort") || defaultSort;
  const loadedPageRef = useRef<string | null>(null);
  const loadedSortRef = useRef<string | null>(null);
  const isExpandedRef = useRef(false);
  const region = searchParams.get("filter[region__in]") || "";

  useEffect(() => {
    async function loadFindings() {
      if (
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
  }, [requirement, scanId, pageNumber, sort, region]);

  const checks = requirement.check_ids || [];
  const checksList = (
    <div className="mb-2 flex items-center">
      <span>{checks.join(", ")}</span>
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
        <div className="p-1">
          <DataTable
            // Remove the updated_at column as compliance is for the last scan
            columns={ColumnFindings.filter(
              (_, index) => index !== 4 && index !== 7,
            )}
            data={expandedFindings || []}
            metadata={findings?.meta}
            disableScroll={true}
          />
        </div>
      );
    }

    return <div>There are no findings for this regions</div>;
  };

  const renderDetails = () => {
    if (!complianceId) {
      return null;
    }

    switch (complianceId) {
      case "ens_rd2022_aws":
        return (
          <div className="w-full">
            <ENSCustomDetails requirement={requirement} />
          </div>
        );
      case "iso27001_2013_aws":
      case "iso27001_2022_aws":
        return (
          <div className="w-full">
            <ISOCustomDetails requirement={requirement} />
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="w-full">
      {renderDetails()}

      {checks.length > 0 && (
        <div className="mb-6 mt-2">
          <Accordion
            items={accordionChecksItems}
            variant="light"
            defaultExpandedKeys={[""]}
            className="rounded-lg bg-white dark:bg-prowler-blue-400"
          />
        </div>
      )}

      {renderFindingsTable()}
    </div>
  );
};
