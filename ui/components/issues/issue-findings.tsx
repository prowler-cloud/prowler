import Link from "next/link";

import { TRIAGE_STATUS_TEXT_CLASS } from "@/components/findings/table/finding-triage-status-control";
import { Card } from "@/components/shadcn/card/card";
import { SeverityBadge } from "@/components/shadcn/table/severity-badge";
import { cn } from "@/lib/utils";
import { FINDING_TRIAGE_STATUS_LABELS } from "@/types/findings-triage";
import { IssueFinding } from "@/types/issues";

interface IssueFindingsProps {
  /** One entry per finding-resource pair, as the graph needs them. */
  findings: IssueFinding[];
  scanId?: string;
  /** All the findings the issue folds; the list shows a bounded preview. */
  total: number;
}

const findingHref = (scanId: string, uid: string) =>
  `/findings?${new URLSearchParams({ "filter[scan__in]": scanId, "filter[uid__in]": uid })}`;

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
  const unique = Array.from(
    new Map(findings.map((finding) => [finding.id, finding])).values(),
  );

  return (
    <section aria-label="Findings">
      <h4 className="mb-3 text-sm font-semibold">
        Findings ({total.toLocaleString()})
      </h4>
      <ul className="grid grid-cols-1 gap-2 lg:grid-cols-2">
        {unique.map((finding) => (
          <li key={finding.id} className="min-w-0">
            <Card variant="inner" padding="md" className="h-full gap-1">
              <div className="flex items-start justify-between gap-3">
                {scanId ? (
                  <Link
                    href={findingHref(scanId, finding.uid)}
                    className="text-text-neutral-primary min-w-0 text-sm break-words hover:underline"
                  >
                    {finding.checkTitle}
                  </Link>
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
                <span
                  className={cn(
                    "shrink-0 text-xs",
                    TRIAGE_STATUS_TEXT_CLASS[finding.triageStatus],
                  )}
                >
                  {FINDING_TRIAGE_STATUS_LABELS[finding.triageStatus]}
                </span>
              </div>
            </Card>
          </li>
        ))}
      </ul>
      {unique.length < total && (
        <p className="text-text-neutral-tertiary mt-2 text-xs">
          Showing {unique.length.toLocaleString()} of {total.toLocaleString()}.
        </p>
      )}
    </section>
  );
};
