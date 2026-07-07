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
  isLoading: boolean;
  error: string | null;
  patchTriageUpdate: (input: UpdateFindingTriageInput) => void;
  reload: () => void;
}

const FINDINGS_LOAD_ERROR = "Could not load findings.";

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
  const [error, setError] = useState<string | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);

  // Depend on the joined value, not the array: the requirement prop gets a
  // fresh identity on every parent render and must not retrigger the fetch.
  const checkIdsKey = checkIds.join(",");
  const isFetchEnabled = enabled && checkIdsKey.length > 0;
  // A skipped fetch is not a pending one; without this the caller would show
  // a skeleton forever for requirements whose fetch never runs.
  const isLoading = isFetchEnabled && findings === null && error === null;

  useEffect(() => {
    if (!isFetchEnabled) {
      return;
    }

    let cancelled = false;

    const loadFindings = async () => {
      setError(null);
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
                providerDict[scan?.relationships?.provider?.data?.id ?? ""];

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
          setError(FINDINGS_LOAD_ERROR);
        }
      }
    };

    loadFindings();

    return () => {
      cancelled = true;
    };
  }, [
    isFetchEnabled,
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

  return {
    findings,
    expandedFindings,
    isLoading,
    error,
    patchTriageUpdate,
    reload,
  };
}
