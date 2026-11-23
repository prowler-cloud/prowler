import { SeverityBadge } from "@/components/shadcn/table/severity-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import { TriageStatusBadge } from "@/components/shared/triage/triage-status-badge";

import type { IssueFindingsProps } from "./types";

const HEADERS = ["Finding", "Severity", "Triage"] as const;

/**
 * The findings the issue folds, laid out like the finding panel's "Other
 * findings" table. Each keeps its own triage: the issue's status answers for
 * the combination, the finding's for whether that one check is right.
 */
export const IssueFindings = ({
  findings,
  total,
  onOpenFinding,
}: IssueFindingsProps) => {
  return (
    <section aria-label="Findings" className="flex flex-col gap-2">
      <div className="flex items-center justify-end">
        <span className="text-text-neutral-tertiary text-sm">
          {findings.length < total
            ? `Showing ${findings.length.toLocaleString()} of ${total.toLocaleString()}`
            : `${total.toLocaleString()} Total Entries`}
        </span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            {HEADERS.map((header) => (
              <TableHead key={header}>
                <span className="text-text-neutral-secondary text-sm font-medium">
                  {header}
                </span>
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((finding) => (
            <TableRow
              key={finding.id}
              className="group cursor-pointer"
              onClick={() => onOpenFinding(finding.id)}
            >
              {/* max-w-0 lets the title take the spare width and truncate. */}
              <TableCell className="w-full max-w-0">
                {/* The row opens the finding; the button is its keyboard stop. */}
                <button
                  type="button"
                  title={finding.checkTitle}
                  className="text-text-neutral-primary block max-w-full truncate text-left text-sm"
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpenFinding(finding.id);
                  }}
                >
                  {finding.checkTitle}
                </button>
                {/* One check fails on several resources: this tells them apart. */}
                <p
                  className="text-text-neutral-tertiary truncate font-mono text-xs"
                  title={finding.resourceUid}
                >
                  {finding.resourceUid}
                </p>
              </TableCell>
              <TableCell>
                <SeverityBadge severity={finding.severity} />
              </TableCell>
              <TableCell>
                <TriageStatusBadge
                  status={finding.triageStatus}
                  showLabel={false}
                />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </section>
  );
};
