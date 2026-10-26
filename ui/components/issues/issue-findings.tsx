import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { SeverityBadge } from "@/components/shadcn/table/severity-badge";
import { TriageStatusBadge } from "@/components/shared/triage/triage-status-badge";
import { MUTED_FILTER } from "@/lib/findings-filters";

import type { IssueFindingsProps } from "./types";

/**
 * The findings the issue folds, each with its own triage. That triage stays on
 * the finding: the issue's status answers for the combination, the finding's
 * for whether that one check is right.
 */
export const IssueFindings = ({
  findings,
  scanId,
  total,
}: IssueFindingsProps) => {
  return (
    <section aria-label="Findings">
      <h4 className="mb-3 text-sm font-semibold">
        Findings ({total.toLocaleString()})
      </h4>
      <ul className="grid grid-cols-1 gap-2 lg:grid-cols-2">
        {findings.map((finding) => (
          <li key={finding.id} className="min-w-0">
            <Card variant="inner" padding="md" className="h-full">
              <div className="flex flex-col gap-1">
                <div className="flex items-start justify-between gap-3">
                  {scanId ? (
                    <div className="min-w-0">
                      <Button
                        asChild
                        variant="link"
                        size="link-sm"
                        className="max-w-full"
                      >
                        <Link
                          href={`/findings?${new URLSearchParams({
                            "filter[scan__in]": scanId,
                            "filter[check_id__in]": finding.checkId,
                            "filter[resource_uid]": finding.resourceUid,
                            "filter[muted]": MUTED_FILTER.INCLUDE,
                            expandedCheckId: finding.checkId,
                          })}`}
                          title={finding.checkTitle}
                        >
                          <span className="truncate">{finding.checkTitle}</span>
                        </Link>
                      </Button>
                    </div>
                  ) : (
                    <span className="text-text-neutral-primary min-w-0 text-sm break-words">
                      {finding.checkTitle}
                    </span>
                  )}
                  <SeverityBadge severity={finding.severity} />
                </div>
                <div className="flex items-baseline justify-between gap-3">
                  <span className="text-text-neutral-tertiary min-w-0 truncate font-mono text-xs">
                    {finding.checkId}
                  </span>
                  <TriageStatusBadge
                    status={finding.triageStatus}
                    showLabel={false}
                  />
                </div>
              </div>
            </Card>
          </li>
        ))}
      </ul>
      {findings.length < total && (
        <p className="text-text-neutral-tertiary mt-2 text-xs">
          Showing {findings.length.toLocaleString()} of {total.toLocaleString()}
          .
        </p>
      )}
    </section>
  );
};
