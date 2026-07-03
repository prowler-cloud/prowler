"use client";

import { useEffect, useState } from "react";

import { getFindings } from "@/actions/findings";
import { applyOptimisticFindingTriageRowsUpdate } from "@/lib/finding-triage";
import { createDict } from "@/lib/utils";
import { FindingProps, FindingsResponse } from "@/types/components";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

interface UseRequirementFindingsOptions {
  enabled: boolean;
  checkIds: string[];
  scanId: string;
  pageNumber: string;
  pageSize: string;
  sort: string;
  region: string;
  mutedFilter: string;
}

interface UseRequirementFindingsReturn {
  findings: FindingsResponse | null;
  expandedFindings: FindingProps[];
  patchTriageUpdate: (input: UpdateFindingTriageInput) => void;
  reload: () => void;
}

export function useRequirementFindings({
  enabled,
  checkIds,
  scanId,
  pageNumber,
  pageSize,
  sort,
  region,
  mutedFilter,
}: UseRequirementFindingsOptions): UseRequirementFindingsReturn {
  const [findings, setFindings] = useState<FindingsResponse | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<FindingProps[]>([]);
  const [reloadNonce, setReloadNonce] = useState(0);

  // Depend on the joined value, not the array: the requirement prop gets a
  // fresh identity on every parent render and must not retrigger the fetch.
  const checkIdsKey = checkIds.join(",");

  useEffect(() => {
    if (!enabled || !checkIdsKey) {
      return;
    }

    let cancelled = false;

    const loadFindings = async () => {
      try {
        const findingsData = await getFindings({
          filters: {
            "filter[check_id__in]": checkIdsKey,
            "filter[scan]": scanId,
            "filter[muted]": mutedFilter,
            ...(region && { "filter[region__in]": region }),
          },
          page: parseInt(pageNumber, 10),
          pageSize: parseInt(pageSize, 10),
          sort: sort.replace(/^\+/, ""),
        });

        if (cancelled) return;

        setFindings(findingsData);

        if (findingsData?.data) {
          const resourceDict = createDict("resources", findingsData);
          const scanDict = createDict("scans", findingsData);
          const providerDict = createDict("providers", findingsData);

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
        if (!cancelled) {
          console.error("Error loading findings:", error);
        }
      }
    };

    loadFindings();

    return () => {
      cancelled = true;
    };
  }, [
    enabled,
    checkIdsKey,
    scanId,
    pageNumber,
    pageSize,
    sort,
    region,
    mutedFilter,
    reloadNonce,
  ]);

  const patchTriageUpdate = (input: UpdateFindingTriageInput) => {
    setExpandedFindings((currentFindings) =>
      applyOptimisticFindingTriageRowsUpdate(currentFindings, input),
    );
  };

  const reload = () => {
    setReloadNonce((value) => value + 1);
  };

  return { findings, expandedFindings, patchTriageUpdate, reload };
}
