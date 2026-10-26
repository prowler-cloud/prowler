"use client";

import { useEffect, useState } from "react";

import { getFindingComplianceFrameworks } from "@/actions/findings/finding-compliance-frameworks";
import {
  buildComplianceDetailHref,
  ComplianceFrameworkChip,
  complianceFrameworkLabel,
} from "@/components/compliance/compliance-framework-chip";
import type { FindingComplianceFramework } from "@/types/compliance-watchlist";
import { IssueFinding } from "@/types/issues";

// shortcut: frameworks are looked up for at most this many distinct checks,
// one request each; add an issue-level endpoint if issues fold more checks.
export const COMPLIANCE_LOOKUP_LIMIT = 6;

type ComplianceState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "loaded"; frameworks: FindingComplianceFramework[] };

interface IssueComplianceProps {
  findings: IssueFinding[];
  scanId?: string;
}

/**
 * The frameworks the issue puts at risk, from Prowler's own per-finding
 * mapping. Frameworks belong to the check, so one finding per check answers
 * for all of them.
 */
export const IssueCompliance = ({ findings, scanId }: IssueComplianceProps) => {
  const [state, setState] = useState<ComplianceState>({ status: "loading" });
  const representatives = Array.from(
    new Map(findings.map((f) => [f.checkId, f.id])).values(),
  ).slice(0, COMPLIANCE_LOOKUP_LIMIT);
  const key = representatives.join(",");

  useEffect(() => {
    let cancelled = false;
    Promise.all(
      key
        .split(",")
        .filter(Boolean)
        .map((id) => getFindingComplianceFrameworks(id)),
    ).then((results) => {
      if (cancelled) return;
      if (results.length > 0 && results.every((r) => r.unavailable)) {
        setState({ status: "unavailable" });
        return;
      }
      const byId = new Map(
        results.flatMap((r) => r.frameworks).map((f) => [f.complianceId, f]),
      );
      // Watchlist first: a public bucket maps into dozens of frameworks, and
      // the ones this organization reports on should not be buried.
      const frameworks = Array.from(byId.values()).sort(
        (a, b) =>
          Number(b.inWatchlist) - Number(a.inWatchlist) ||
          complianceFrameworkLabel(a).localeCompare(
            complianceFrameworkLabel(b),
          ),
      );
      setState({ status: "loaded", frameworks });
    });
    return () => {
      cancelled = true;
    };
  }, [key]);

  const open = (framework: FindingComplianceFramework) => {
    if (!scanId) return;
    window.open(
      buildComplianceDetailHref({
        complianceId: framework.complianceId,
        framework: framework.framework || framework.name,
        version: framework.version,
        scanId,
        regionFilter: null,
      }),
      "_blank",
    );
  };

  return (
    <section aria-label="Compliance affected">
      <h4 className="mb-3 text-sm font-semibold">Compliance affected</h4>
      {state.status === "loading" ? (
        <p role="status" className="text-text-neutral-tertiary text-sm">
          Loading frameworks…
        </p>
      ) : state.status === "unavailable" ? (
        <p className="text-text-neutral-tertiary text-sm">
          Could not load the frameworks for this issue.
        </p>
      ) : state.frameworks.length === 0 ? (
        <p className="text-text-neutral-tertiary text-sm">
          None of the findings behind this issue map to a framework requirement.
        </p>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          {state.frameworks.map((framework) => (
            <ComplianceFrameworkChip
              key={framework.complianceId}
              framework={framework}
              isNavigable={Boolean(scanId)}
              onOpen={open}
            />
          ))}
        </div>
      )}
    </section>
  );
};
