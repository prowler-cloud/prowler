"use client";

import { AlertTriangle } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useMemo } from "react";

import {
  loadLatestFindingTriageNote,
  updateFindingTriage,
} from "@/actions/findings";
import {
  getStandaloneFindingColumns,
  SkeletonTableFindings,
} from "@/components/findings/table";
import { ProviderBadgeIcon } from "@/components/icons/providers-badge/provider-badge-icon";
import { Alert, AlertDescription, Button } from "@/components/shadcn";
import { Accordion } from "@/components/ui/accordion/Accordion";
import { DataTable } from "@/components/ui/table";
import { StatusFindingBadge } from "@/components/ui/table/status-finding-badge";
import { FINDINGS_DEFAULT_SORT, MUTED_FILTER } from "@/lib";
import { INVALID_CONFIG_NOTE } from "@/lib/compliance/commons";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import { shouldRefreshAfterTriageUpdate } from "@/lib/finding-triage";
import { getProviderLabel } from "@/lib/providers/provider-display";
import {
  CrossProviderRequirement,
  Requirement,
  RequirementStatus,
} from "@/types/compliance";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

import { useRequirementFindings } from "./use-requirement-findings";

interface ClientAccordionContentProps {
  requirement: Requirement;
  scanId: string;
  framework: string;
  disableFindings?: boolean;
}

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
  const searchParams = useSearchParams();
  const pageNumber = searchParams.get("page") || "1";
  const pageSize = searchParams.get("pageSize") || "10";
  const complianceId = searchParams.get("complianceId");
  const openFindingId = searchParams.get("id");
  const sort = searchParams.get("sort") || FINDINGS_DEFAULT_SORT;
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

  const checks = requirement.check_ids || [];

  // Identifies *what* findings this requirement should show — which scans,
  // checks and region it's scoped to. Provider-type/account/region filters
  // on the page narrow the fetch server-side without necessarily changing
  // page/sort/mute, so those alone aren't enough to tell a stale fetch from
  // a fresh one: an already-expanded row would otherwise keep showing
  // findings from providers or regions the user just filtered out.
  const scopeSignature = isCrossProvider
    ? JSON.stringify({ scanIdsByProvider, checkIdsByProvider, region })
    : `${scanId}|${checks.join(",")}|${region}`;

  const {
    findings,
    expandedFindings,
    isLoading,
    error,
    patchTriageUpdate,
    reload,
  } = useRequirementFindings({
    enabled:
      !disableFindings &&
      checks.length > 0 &&
      requirement.status !== "No findings",
    checkIds: checks,
    scanId,
    pageNumber,
    pageSize,
    sort,
    region,
    mutedFilter,
    isCrossProvider,
    scanIdsByProvider,
    checkIdsByProvider,
    scopeSignature,
  });

  const handleTriageUpdate = async (input: UpdateFindingTriageInput) => {
    await updateFindingTriage(input);

    // Mutelist-shortcut statuses mute the finding server-side; refetch so the
    // list honors the muted filter, matching the resource drawer behavior.
    if (shouldRefreshAfterTriageUpdate(input)) {
      reload();
      return;
    }

    patchTriageUpdate(input);
  };

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
    if (error) {
      return (
        <Alert variant="error" className="mt-3">
          <AlertTriangle />
          <AlertDescription className="flex flex-wrap items-center gap-2">
            <span>{error}</span>
            <Button
              variant="link"
              size="link-sm"
              className="h-auto p-0"
              onClick={reload}
            >
              Try again
            </Button>
          </AlertDescription>
        </Alert>
      );
    }

    if (isLoading && requirement.status !== "MANUAL") {
      return <SkeletonTableFindings />;
    }

    if (findings?.data?.length && findings.data.length > 0) {
      return (
        <>
          <h4 className="mb-2 text-sm font-medium">Findings</h4>

          <DataTable
            columns={getStandaloneFindingColumns({
              openFindingId,
              onTriageUpdateAction: handleTriageUpdate,
              onTriageNoteLoadAction: loadLatestFindingTriageNote,
            })}
            data={expandedFindings}
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
