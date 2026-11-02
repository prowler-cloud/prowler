"use client";

import { useEffect, useState } from "react";

import { getFindingComplianceFrameworks } from "@/actions/findings/finding-compliance-frameworks";
import {
  buildComplianceDetailHref,
  ComplianceFrameworkChip,
  complianceFrameworkLabel,
} from "@/components/compliance/compliance-framework-chip";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import type { FindingComplianceFramework } from "@/types/compliance-watchlist";
import { IssueFinding } from "@/types/issues";

// shortcut: frameworks are looked up for at most this many distinct checks,
// one request each; add an issue-level endpoint if issues fold more checks.
export const COMPLIANCE_LOOKUP_LIMIT = 6;

type ComplianceState =
  | { status: "loading" }
  | { status: "unavailable" }
  | {
      status: "loaded";
      frameworks: FindingComplianceFramework[];
      /** Some lookups failed, so frameworks may be missing. */
      partial: boolean;
    };

interface IssueComplianceProps {
  findings: IssueFinding[];
  scanId?: string;
  /** `findings` is a capped preview of a larger issue. */
  truncated?: boolean;
}

/**
 * The frameworks the issue puts at risk, from Prowler's own per-finding
 * mapping. Frameworks belong to the check, so one finding per check answers
 * for all of them.
 */
export const IssueCompliance = ({
  findings,
  scanId,
  truncated = false,
}: IssueComplianceProps) => {
  const [state, setState] = useState<ComplianceState>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  const checks = new Map(findings.map((f) => [f.checkId, f.id]));
  const representatives = Array.from(checks.values()).slice(
    0,
    COMPLIANCE_LOOKUP_LIMIT,
  );
  const key = representatives.join(",");

  useEffect(() => {
    let cancelled = false;
    Promise.all(
      key
        .split(",")
        .filter(Boolean)
        .map((id) => getFindingComplianceFrameworks(id)),
    )
      .then((results) => {
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
        setState({
          status: "loaded",
          frameworks,
          partial: results.some((r) => r.unavailable),
        });
      })
      .catch(() => {
        if (!cancelled) setState({ status: "unavailable" });
      });
    return () => {
      cancelled = true;
    };
  }, [key, attempt]);

  const retry = () => {
    setState({ status: "loading" });
    setAttempt((value) => value + 1);
  };

  const incomplete =
    state.status === "loaded" &&
    (state.partial || truncated || checks.size > COMPLIANCE_LOOKUP_LIMIT);

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

  // Laid out like the finding panel's "Compliance Frameworks" header row.
  return (
    <section aria-label="Compliance affected" className="flex flex-col gap-1.5">
      <span className="text-text-neutral-tertiary text-xs font-medium">
        Compliance Frameworks:
      </span>
      {state.status === "loading" ? (
        <div className="flex flex-wrap items-center gap-2">
          <span role="status" className="sr-only">
            Loading frameworks…
          </span>
          <Skeleton className="size-7 rounded-md" />
          <Skeleton className="size-7 rounded-md" />
          <Skeleton className="size-7 rounded-md" />
        </div>
      ) : state.status === "unavailable" ? (
        <IssuesLoadError
          message="Could not load the frameworks for this issue."
          onRetry={retry}
        />
      ) : (
        <>
          {state.frameworks.length === 0 ? (
            <p className="text-text-neutral-tertiary text-xs">
              {incomplete
                ? "None of the findings checked map to a framework requirement."
                : "None of the findings behind this issue map to a framework requirement."}
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
          {incomplete && (
            <p className="text-text-neutral-tertiary text-xs">
              Not every finding could be checked, so this list may be
              incomplete.
            </p>
          )}
        </>
      )}
    </section>
  );
};
