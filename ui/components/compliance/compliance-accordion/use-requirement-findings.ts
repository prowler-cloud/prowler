"use client";

import { useEffect, useState } from "react";

import { getFindings } from "@/actions/findings";
import { applyOptimisticFindingTriageRowsUpdate } from "@/lib/finding-triage";
import { createDict } from "@/lib/utils";
import { FindingProps, FindingsResponse } from "@/types/components";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

// ``included`` is part of the JSON:API envelope but ``FindingsResponse`` only
// models ``data`` + ``meta``. Carry it locally so ``createDict`` (which reads
// ``data.included`` at runtime) can resolve the provider/scan/resource
// relationships per row.
type FindingsResponseLike = FindingsResponse & {
  included?: { type: string; id: string }[];
};

interface UseRequirementFindingsOptions {
  enabled: boolean;
  checkIds: string[];
  scanId: string;
  pageNumber: string;
  pageSize: string;
  sort: string;
  region: string;
  mutedFilter: string;
  // Cross-provider augmentation (universal frameworks). When
  // ``isCrossProvider`` is true the hook fans out one fetch per contributing
  // scan and merges the JSON:API ``data`` + ``included`` arrays instead of
  // issuing a single per-scan request.
  isCrossProvider?: boolean;
  scanIdsByProvider?: Record<string, string[]>;
  checkIdsByProvider?: Record<string, string[]>;
  // Identifies *what* findings the fetch is scoped to (scans, checks,
  // region). Provider/account/region filters narrow the fetch server-side
  // without changing page/sort/mute, so this is the canonical trigger for a
  // fresh cross-provider fetch — it serializes ``scanIdsByProvider`` /
  // ``checkIdsByProvider`` (which get a fresh identity on every parent render
  // and so can't be effect dependencies themselves).
  scopeSignature?: string;
}

interface UseRequirementFindingsReturn {
  findings: FindingsResponse | null;
  expandedFindings: FindingProps[];
  isLoading: boolean;
  error: string | null;
  // Cross-provider only: true when at least one — but not every — per-scan
  // request failed, so the merged view is missing some providers' findings.
  // The caller surfaces a warning instead of presenting the partial data as
  // complete.
  isPartial: boolean;
  patchTriageUpdate: (input: UpdateFindingTriageInput) => void;
  reload: () => void;
}

const FINDINGS_LOAD_ERROR = "Could not load findings.";

// Merge the per-scan responses of a cross-provider fan-out into a single
// JSON:API-shaped envelope: concatenate every ``data`` row, dedupe the
// ``included`` records by ``(type, id)`` (the same provider/scan object
// repeats across responses), and sum the per-scan counts.
const mergeCrossProviderResponses = (
  responses: unknown[],
  page: number,
): FindingsResponseLike => {
  const allData: FindingProps[] = [];
  const allIncluded: { type: string; id: string }[] = [];
  let totalCount = 0;

  for (const r of responses) {
    if (!r || typeof r !== "object" || !("data" in r)) continue;
    const typedResponse = r as FindingsResponseLike;
    allData.push(...(typedResponse.data || []));
    allIncluded.push(...(typedResponse.included || []));
    totalCount += typedResponse?.meta?.pagination?.count || 0;
  }

  const dedupedIncluded: typeof allIncluded = [];
  const seenIncluded = new Set<string>();
  for (const entry of allIncluded) {
    const key = `${entry.type}|${entry.id}`;
    if (seenIncluded.has(key)) continue;
    seenIncluded.add(key);
    dedupedIncluded.push(entry);
  }

  return {
    data: allData,
    included: dedupedIncluded,
    meta: {
      pagination: { page, pages: 1, count: totalCount },
      version: "",
    },
  };
};

export function useRequirementFindings({
  enabled,
  checkIds,
  scanId,
  pageNumber,
  pageSize,
  sort,
  region,
  mutedFilter,
  isCrossProvider = false,
  scanIdsByProvider,
  checkIdsByProvider,
  scopeSignature,
}: UseRequirementFindingsOptions): UseRequirementFindingsReturn {
  const [findings, setFindings] = useState<FindingsResponse | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<FindingProps[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isPartial, setIsPartial] = useState(false);
  const [reloadNonce, setReloadNonce] = useState(0);

  // Depend on the joined value, not the array: the requirement prop gets a
  // fresh identity on every parent render and must not retrigger the fetch.
  const checkIdsKey = checkIds.join(",");
  const hasCrossProviderScans = Boolean(
    scanIdsByProvider && Object.keys(scanIdsByProvider).length > 0,
  );
  const isFetchEnabled =
    enabled &&
    (isCrossProvider ? hasCrossProviderScans : checkIdsKey.length > 0);
  // A skipped fetch is not a pending one; without this the caller would show
  // a skeleton forever for requirements whose fetch never runs.
  const isLoading = isFetchEnabled && findings === null && error === null;

  useEffect(() => {
    if (!isFetchEnabled) {
      return;
    }

    let cancelled = false;

    // Derive the table rows from a fetched response, resolving each finding's
    // scan/resource/provider from the ``included`` envelope. Kept as state
    // (not a render-time memo) so ``patchTriageUpdate`` can optimistically
    // mutate a single row without a refetch.
    const expandFindings = (findingsData: FindingsResponseLike) => {
      if (!findingsData?.data) return;
      const resourceDict = createDict("resources", findingsData);
      const scanDict = createDict("scans", findingsData);
      const providerDict = createDict("providers", findingsData);

      const expandedData = findingsData.data.map((finding: FindingProps) => {
        const scan = scanDict[finding.relationships?.scan?.data?.id];
        const resource =
          resourceDict[finding.relationships?.resources?.data?.[0]?.id];
        const provider =
          providerDict[scan?.relationships?.provider?.data?.id ?? ""];

        return {
          ...finding,
          relationships: { scan, resource, provider },
        };
        // The resolved scan/resource/provider come from ``createDict`` as
        // ``IncludedApiItem`` records, which don't line up with the strict
        // ``FindingProps.relationships`` shape; the table consumes them by
        // the same keys, so narrow back to ``FindingProps`` at the seam.
      }) as unknown as FindingProps[];
      setExpandedFindings(expandedData);
    };

    const loadFindings = async () => {
      setError(null);
      setIsPartial(false);
      try {
        const encodedSort = sort.replace(/^\+/, "");

        if (isCrossProvider) {
          // Fetch findings scoped to each contributing scan in parallel and
          // merge them. ``scanIdsByProvider[providerKey]`` is a list because a
          // tenant can have N accounts of the same type — fan out one
          // ``filter[scan]`` request per account, all under the same provider
          // key, scoped to that provider's declared checks. Server-side
          // filters (RLS, muted, region) apply per query individually.
          const jobs = Object.entries(scanIdsByProvider ?? {}).flatMap(
            ([providerKey, scanIds]) => {
              const checks = (checkIdsByProvider?.[providerKey] ?? []).join(
                ",",
              );
              if (!checks || !Array.isArray(scanIds) || scanIds.length === 0) {
                return [];
              }
              return scanIds.map((scanIdForAccount) => ({
                scanIdForAccount,
                checks,
              }));
            },
          );

          const responses = await Promise.all(
            jobs.map(({ scanIdForAccount, checks }) =>
              getFindings({
                filters: {
                  "filter[check_id__in]": checks,
                  "filter[scan]": scanIdForAccount,
                  "filter[muted]": mutedFilter,
                  ...(region && { "filter[region__in]": region }),
                },
                page: parseInt(pageNumber, 10),
                pageSize: parseInt(pageSize, 10),
                sort: encodedSort,
              }),
            ),
          );

          if (cancelled) return;

          // ``getFindings`` resolves to ``undefined`` on a failed request
          // rather than throwing, so a per-scan failure would otherwise be
          // silently dropped from the merge and the view would look complete.
          const failedCount = responses.filter(
            (r) => !r || typeof r !== "object" || !("data" in r),
          ).length;

          // Every request failed — treat it as a hard error (same surface as
          // the per-scan branch) instead of rendering an empty "no findings".
          if (jobs.length > 0 && failedCount === jobs.length) {
            setError(FINDINGS_LOAD_ERROR);
            return;
          }

          const merged = mergeCrossProviderResponses(
            responses,
            parseInt(pageNumber, 10),
          );
          setFindings(merged);
          expandFindings(merged);
          // Some — but not all — scans failed: keep the successful data but
          // flag the merge as incomplete so the caller can warn the user.
          setIsPartial(failedCount > 0);
          return;
        }

        // Per-scan branch (single request).
        const findingsData = await getFindings({
          filters: {
            "filter[check_id__in]": checkIdsKey,
            "filter[scan]": scanId,
            "filter[muted]": mutedFilter,
            ...(region && { "filter[region__in]": region }),
          },
          page: parseInt(pageNumber, 10),
          pageSize: parseInt(pageSize, 10),
          sort: encodedSort,
        });

        if (cancelled) return;

        setFindings(findingsData);
        expandFindings(findingsData as FindingsResponseLike);
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
    // ``scanIdsByProvider`` / ``checkIdsByProvider`` are intentionally read
    // via ``scopeSignature`` rather than listed directly: they get a fresh
    // identity on every parent render and would trigger a refetch storm.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    isFetchEnabled,
    isCrossProvider,
    checkIdsKey,
    scanId,
    pageNumber,
    pageSize,
    sort,
    region,
    mutedFilter,
    scopeSignature,
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
    isPartial,
    patchTriageUpdate,
    reload,
  };
}
