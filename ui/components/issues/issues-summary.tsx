import { IssuesOverviewAttributes } from "@/types/issues";

const count = (value: number, noun: string) =>
  `${value.toLocaleString()} ${noun}${value === 1 ? "" : "s"}`;

/**
 * The reduction the page makes, as one line under the title. Per-verdict
 * counts live on the verdict tabs, so they are not repeated here.
 */
export const IssuesSummary = ({
  summary,
}: {
  summary: IssuesOverviewAttributes;
}) => (
  <p className="text-text-neutral-tertiary text-sm">
    <span className="text-text-neutral-primary font-medium">
      {count(summary.issues, "issue")}
    </span>{" "}
    folded from{" "}
    <span className="text-text-neutral-primary font-medium">
      {count(summary.findings, "failed finding")}
    </span>
    {summary.not_exploitable_findings > 0 &&
      ` · ${count(summary.not_exploitable_findings, "finding")} already covered by a control`}
  </p>
);
