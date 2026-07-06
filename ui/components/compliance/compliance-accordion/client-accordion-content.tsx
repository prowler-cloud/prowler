"use client";

import { AlertTriangle } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";

import { getFindings } from "@/actions/findings/findings";
import {
  getStandaloneFindingColumns,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { ProviderBadgeIcon } from "@/components/icons/providers-badge/provider-badge-icon";
import { Alert, AlertDescription } from "@/components/shadcn";
import { Accordion } from "@/components/ui/accordion/Accordion";
import { DataTable } from "@/components/ui/table";
import { StatusFindingBadge } from "@/components/ui/table/status-finding-badge";
import { createDict, FINDINGS_DEFAULT_SORT, MUTED_FILTER } from "@/lib";
import { INVALID_CONFIG_NOTE } from "@/lib/compliance/commons";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import { getProviderLabel } from "@/lib/providers/provider-display";
import {
  CrossProviderRequirement,
  Requirement,
  RequirementStatus,
} from "@/types/compliance";
import { FindingProps, FindingsResponse } from "@/types/components";

interface ClientAccordionContentProps {
  requirement: Requirement;
  scanId: string;
  framework: string;
  disableFindings?: boolean;
}

// ``included`` is part of the JSON:API envelope but the ``FindingsResponse``
// interface only models ``data`` + ``meta``. Carry it locally so ``createDict``
// (which inspects ``data.included`` at runtime) can resolve the
// provider/scan/resource relationships per row.
type FindingsResponseLike = FindingsResponse & {
  included?: { type: string; id: string }[];
};

const toFindingStatus = (status: RequirementStatus) => {
  // FindingStatus shares the same wire values for PASS/FAIL/MANUAL.
  return status === "No findings" ? "MANUAL" : status;
};

export const ClientAccordionContent = ({
  requirement,
  framework,
  scanId,
  disableFindings = false,
}: ClientAccordionContentProps) => {
  const [findings, setFindings] = useState<FindingsResponse | null>(null);
  const searchParams = useSearchParams();
  const pageNumber = searchParams.get("page") || "1";
  const pageSize = searchParams.get("pageSize") || "10";
  const complianceId = searchParams.get("complianceId");
  const openFindingId = searchParams.get("id");
  const sort = searchParams.get("sort") || FINDINGS_DEFAULT_SORT;
  const loadedPageRef = useRef<string | null>(null);
  const loadedPageSizeRef = useRef<string | null>(null);
  const loadedSortRef = useRef<string | null>(null);
  const loadedMutedRef = useRef<string | null>(null);
  const loadedScopeRef = useRef<string | null>(null);
  const isExpandedRef = useRef(false);
  const region = searchParams.get("filter[region__in]") || "";
  // Respect the user's muted preference from the URL; default to EXCLUDE
  // so the requirement view stays consistent with every other findings
  // surface in the app (findings page, resource drawer, overview widgets).
  const mutedFilter = searchParams.get("filter[muted]") || MUTED_FILTER.EXCLUDE;

  // Cross-provider requirements carry these augmentation maps; per-scan
  // requirements leave them undefined. Narrow once at the seam so the
  // hot paths below don't need repeated casts.
  const xprov = requirement as CrossProviderRequirement;
  const scanIdsByProvider = xprov.scan_ids_by_provider;
  const checkIdsByProvider = xprov.check_ids_by_provider;
  const providersBreakdown = xprov.providers;
  const isCrossProvider =
    !!scanIdsByProvider && Object.keys(scanIdsByProvider).length > 0;
  // Identifies *what* findings this requirement should show — which scans,
  // checks and region it's scoped to. Provider-type/account/region filters
  // on the page narrow the fetch server-side without necessarily changing
  // page/sort/mute, so those alone aren't enough to tell a stale fetch from
  // a fresh one: an already-expanded row would otherwise keep showing
  // findings from providers or regions the user just filtered out.
  const scopeSignature = isCrossProvider
    ? JSON.stringify({ scanIdsByProvider, checkIdsByProvider, region })
    : `${scanId}|${(requirement.check_ids || []).join(",")}|${region}`;

  useEffect(() => {
    // Guard against a slower earlier request resolving after a newer one and
    // clobbering the table (race on fast page/sort/filter changes).
    let cancelled = false;

    async function loadFindings() {
      if (disableFindings || requirement.status === "No findings") return;
      if (
        loadedPageRef.current === pageNumber &&
        loadedPageSizeRef.current === pageSize &&
        loadedSortRef.current === sort &&
        loadedMutedRef.current === mutedFilter &&
        loadedScopeRef.current === scopeSignature &&
        isExpandedRef.current
      ) {
        return;
      }

      // Mark "loaded" for these exact params only once the fetch actually
      // commits (below, right before each ``setFindings``) — not here. If a
      // dependency changes (e.g. a sibling re-render gives ``requirement`` a
      // new identity) while this fetch is in flight, the effect cleanup
      // flips ``cancelled`` and the commit is skipped; marking the refs
      // upfront would make the *next* effect run see "already loaded" and
      // skip re-fetching too, permanently stranding the component with
      // ``findings`` stuck at ``null``.

      try {
        const encodedSort = sort.replace(/^\+/, "");

        if (isCrossProvider) {
          // Fetch findings scoped to each contributing scan in parallel
          // and merge the JSON:API ``data`` + ``included`` arrays so
          // the unified table can resolve the provider/scan/resource
          // relationships per row. Server-side filters apply per scan
          // (the API enforces RLS on each query individually).
          //
          // ``scanIdsByProvider[providerKey]`` is a list because a
          // tenant can have N accounts of the same type — fan out one
          // ``filter[scan]`` request per account, all under the same
          // provider key.
          const entries = Object.entries(scanIdsByProvider!);
          const jobs = entries.flatMap(([providerKey, scanIds]) => {
            const checks = (checkIdsByProvider?.[providerKey] ?? []).join(",");
            if (!checks || !Array.isArray(scanIds) || scanIds.length === 0) {
              return [];
            }
            return scanIds.map((scanIdForAccount) => ({
              providerKey,
              scanIdForAccount,
              checks,
            }));
          });
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
                sort: encodedSort,
              }),
            ),
          );

          const allData: FindingProps[] = [];
          const allIncluded: { type: string; id: string }[] = [];
          let totalCount = 0;
          for (const r of responses) {
            if (!r || !("data" in r)) continue;
            const typedResponse = r as FindingsResponseLike;
            allData.push(...(typedResponse.data || []));
            allIncluded.push(...(typedResponse.included || []));
            totalCount += typedResponse?.meta?.pagination?.count || 0;
          }

          // Each scan response includes its provider/scan record;
          // across N responses the same provider object appears N
          // times. Dedupe by ``(type, id)`` so the subsequent
          // ``createDict`` passes stop allocating duplicate entries.
          const dedupedIncluded: typeof allIncluded = [];
          const seenIncluded = new Set<string>();
          for (const entry of allIncluded) {
            const key = `${entry.type}|${entry.id}`;
            if (seenIncluded.has(key)) continue;
            seenIncluded.add(key);
            dedupedIncluded.push(entry);
          }

          const merged: FindingsResponseLike = {
            data: allData,
            included: dedupedIncluded,
            meta: {
              pagination: {
                page: parseInt(pageNumber, 10),
                pages: 1,
                count: totalCount,
              },
              version: "",
            },
          };
          if (cancelled) return;
          loadedPageRef.current = pageNumber;
          loadedPageSizeRef.current = pageSize;
          loadedSortRef.current = sort;
          loadedMutedRef.current = mutedFilter;
          loadedScopeRef.current = scopeSignature;
          isExpandedRef.current = true;
          setFindings(merged);
          return;
        }

        // Per-scan branch (existing behaviour).
        if (!requirement.check_ids?.length) return;
        const checkIds = requirement.check_ids;
        const findingsData = await getFindings({
          filters: {
            "filter[check_id__in]": checkIds.join(","),
            "filter[scan]": scanId,
            "filter[muted]": mutedFilter,
            ...(region && { "filter[region__in]": region }),
          },
          page: parseInt(pageNumber, 10),
          pageSize: parseInt(pageSize, 10),
          sort: encodedSort,
        });

        if (cancelled) return;
        loadedPageRef.current = pageNumber;
        loadedPageSizeRef.current = pageSize;
        loadedSortRef.current = sort;
        loadedMutedRef.current = mutedFilter;
        loadedScopeRef.current = scopeSignature;
        isExpandedRef.current = true;
        setFindings(findingsData);
      } catch (error) {
        console.error("Error loading findings:", error);
      }
    }

    loadFindings();

    return () => {
      cancelled = true;
    };
  }, [
    requirement,
    scanId,
    pageNumber,
    pageSize,
    sort,
    region,
    mutedFilter,
    scopeSignature,
    disableFindings,
    isCrossProvider,
    scanIdsByProvider,
    checkIdsByProvider,
  ]);

  // Expand each finding with its resource/scan/provider. Derived from
  // ``findings`` rather than stored as separate state so the table can never
  // drift out of sync with the fetched rows.
  const expandedFindings = useMemo<FindingProps[]>(() => {
    if (!findings?.data) return [];
    const resourceDict = createDict("resources", findings);
    const scanDict = createDict("scans", findings);
    const providerDict = createDict("providers", findings);
    return findings.data.map((finding: FindingProps) => {
      const scan = scanDict[finding.relationships?.scan?.data?.id];
      const resource =
        resourceDict[finding.relationships?.resources?.data?.[0]?.id];
      const provider = providerDict[scan?.relationships?.provider?.data?.id];
      return {
        ...finding,
        relationships: { scan, resource, provider },
      };
    }) as unknown as FindingProps[];
  }, [findings]);

  // Per-provider finding tallies for the cross-provider breakdown. Derived
  // from the merged ``findings`` (mapping each row to its provider via
  // ``scan_ids_by_provider``) so the counts always match the unified table.
  const providerFindingStats = useMemo(() => {
    const count: Record<string, number> = {};
    const pass: Record<string, number> = {};
    const fail: Record<string, number> = {};
    if (!isCrossProvider || !scanIdsByProvider) {
      return { count, pass, fail };
    }
    const scanToProvider = new Map<string, string>();
    for (const [providerKey, scanIds] of Object.entries(scanIdsByProvider)) {
      count[providerKey] = 0;
      pass[providerKey] = 0;
      fail[providerKey] = 0;
      if (Array.isArray(scanIds)) {
        for (const sid of scanIds) scanToProvider.set(sid, providerKey);
      }
    }
    for (const row of findings?.data ?? []) {
      const sid = row.relationships?.scan?.data?.id;
      const providerKey = sid ? scanToProvider.get(sid) : undefined;
      if (!providerKey) continue;
      count[providerKey] += 1;
      const status = row.attributes?.status;
      if (status === "PASS") pass[providerKey] += 1;
      else if (status === "FAIL") fail[providerKey] += 1;
    }
    return { count, pass, fail };
  }, [findings, isCrossProvider, scanIdsByProvider]);

  const renderDetails = () => {
    if (!complianceId) {
      return null;
    }

    const mapper = getComplianceMapper(framework);
    const detailsComponent = mapper.getDetailsComponent(requirement);

    return <div className="w-full">{detailsComponent}</div>;
  };

  const renderProviderBreakdown = () => {
    if (!providersBreakdown) return null;
    const entries = Object.entries(providersBreakdown);
    if (entries.length === 0) return null;
    // ``findings`` is null until the lazy fetch resolves; in that case
    // surface a neutral placeholder so the user does not see ``0`` and
    // mistake it for "no findings". Once findings load, the count maps
    // are the authoritative source — they match the unified table below
    // row-for-row.
    const findingsLoaded = findings !== null;
    return (
      <div className="my-4">
        <h4 className="mb-2 text-sm font-medium">Per-Provider Breakdown</h4>
        <div className="border-border-neutral-secondary overflow-hidden rounded-md border">
          <table className="w-full text-xs">
            <thead className="bg-default-100">
              <tr className="text-text-neutral-secondary text-left">
                <th className="px-3 py-2 font-semibold">Provider</th>
                <th className="px-3 py-2 font-semibold">Status</th>
                <th className="px-3 py-2 font-semibold">Findings</th>
                <th className="px-3 py-2 font-semibold">Pass / Fail</th>
                <th className="px-3 py-2 font-semibold">Scan ID</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(([providerKey, providerStatus]) => {
                const label = getProviderLabel(providerKey);
                const scanIdsForProvider =
                  scanIdsByProvider?.[providerKey] ?? [];
                const accountCount = scanIdsForProvider.length;
                const findingsCount = providerFindingStats.count[providerKey];
                const passCount = providerFindingStats.pass[providerKey] ?? 0;
                const failCount = providerFindingStats.fail[providerKey] ?? 0;
                return (
                  <tr
                    key={providerKey}
                    className="border-border-neutral-secondary border-t"
                  >
                    <td className="px-3 py-2 align-top font-medium">
                      <div className="flex flex-col gap-0.5">
                        <span>{label}</span>
                        {accountCount > 1 && (
                          <span className="text-text-neutral-secondary text-[10px] tracking-wider uppercase">
                            {accountCount} accounts
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2 align-top">
                      <StatusFindingBadge
                        status={toFindingStatus(providerStatus)}
                      />
                    </td>
                    <td className="text-text-neutral-secondary px-3 py-2 align-top">
                      {findingsLoaded ? (findingsCount ?? 0) : "—"}
                    </td>
                    <td className="px-3 py-2 align-top">
                      {findingsLoaded ? (
                        <span className="font-mono">
                          <span className="text-bg-pass">{passCount}</span>
                          <span className="text-text-neutral-secondary">
                            {" / "}
                          </span>
                          <span className="text-bg-fail">{failCount}</span>
                        </span>
                      ) : (
                        <span className="text-text-neutral-secondary">—</span>
                      )}
                    </td>
                    <td
                      className="text-text-neutral-secondary px-3 py-2 align-top font-mono text-[11px] break-all"
                      title={scanIdsForProvider.join("\n")}
                    >
                      {accountCount === 0 ? (
                        "—"
                      ) : (
                        <ul className="flex flex-col gap-0.5">
                          {scanIdsForProvider.map((sid) => (
                            <li key={sid}>{sid}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  if (disableFindings) {
    return (
      <div className="w-full">
        {renderDetails()}
        {renderProviderBreakdown()}
        <p className="mt-3 mb-1 text-sm font-medium text-gray-800 dark:text-gray-200">
          ⚠️ This requirement has no checks; therefore, there are no findings.
        </p>
      </div>
    );
  }

  const checks = requirement.check_ids || [];
  // In cross-provider mode the universal framework declares the same
  // requirement against multiple providers, often with disjoint check
  // sets. Show a per-provider grouping so the user can audit which checks
  // belong to which scan instead of staring at a flattened comma list.
  // Per-scan mode keeps the original flat layout — there's only one
  // provider, so a grouping would be visual noise.
  const checkIdsByProviderEntries = checkIdsByProvider
    ? Object.entries(checkIdsByProvider).filter(
        ([, ids]) => Array.isArray(ids) && ids.length > 0,
      )
    : [];
  const showPerProviderChecks =
    isCrossProvider && checkIdsByProviderEntries.length > 0;

  const checksList = showPerProviderChecks ? (
    <div className="flex flex-col gap-3 px-3 pb-2">
      {checkIdsByProviderEntries.map(([providerKey, ids], idx) => {
        const label = getProviderLabel(providerKey);
        return (
          <div
            key={providerKey}
            className={`flex flex-col gap-2 ${
              idx > 0
                ? "border-t border-gray-200 pt-3 dark:border-gray-800"
                : ""
            }`}
          >
            <div className="flex items-center gap-2">
              <ProviderBadgeIcon providerKey={providerKey} size={16} />
              <span className="text-text-neutral-primary text-xs font-semibold">
                {label}
              </span>
              <span className="text-text-neutral-secondary text-xs">
                {ids.length} {ids.length === 1 ? "check" : "checks"}
              </span>
            </div>
            {/* Soft filled chips, no border: bordered pills read as a "wall
                of boxes" once there are 5-10 of them, but bare text (no
                fill at all) reads as unstyled/unfinished and a fixed-width
                grid left ragged gaps for the shorter ids. A tinted
                background gives each check enough visual weight to look
                intentional while staying quiet — flex-wrap sizes every
                chip to its own content so nothing is cramped or stranded
                in dead space regardless of how long the check id is. */}
            <ul className="flex flex-wrap gap-1.5 pl-6">
              {ids.map((id) => (
                <li
                  key={id}
                  className="bg-default-100 hover:bg-default-200 text-text-neutral-secondary dark:bg-default-100/10 dark:hover:bg-default-100/20 rounded-md px-2 py-1 font-mono text-[11px] transition-colors"
                >
                  {id}
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  ) : (
    <div className="flex items-center px-2 text-sm">
      <div className="w-full flex-col">
        <div className="mt-[-8px] mb-1 h-1 w-full border-b border-gray-200 dark:border-gray-800" />
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
            columns={getStandaloneFindingColumns({ openFindingId })}
            data={expandedFindings || []}
            metadata={findings?.meta}
            disableScroll={true}
          />
        </>
      );
    }

    return (
      <div className="mt-3 mb-1 text-sm font-medium text-gray-800 dark:text-gray-200">
        ⚠️ There are no findings for these regions
      </div>
    );
  };

  return (
    <div className="w-full">
      {requirement.invalid_config && (
        <Alert variant="warning" className="mb-3">
          <AlertTriangle />
          <AlertDescription>{INVALID_CONFIG_NOTE}</AlertDescription>
        </Alert>
      )}

      {renderDetails()}

      {renderProviderBreakdown()}

      {checks.length > 0 && (
        <div className="my-4">
          <Accordion
            items={accordionChecksItems}
            variant="light"
            defaultExpandedKeys={[""]}
            className="dark:bg-prowler-blue-400 rounded-lg bg-gray-50"
          />
        </div>
      )}

      {renderFindingsTable()}
    </div>
  );
};
