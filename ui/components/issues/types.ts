import type { FindingTriageStatus } from "@/types/findings-triage";
import type { IssueFinding } from "@/types/issues";

export interface IssueFindingsProps {
  /** One entry per finding, with a resource to open in the group drill-down. */
  findings: IssueFinding[];
  scanId?: string;
  /** All the findings the issue folds; the list shows a bounded preview. */
  total: number;
}

export interface IssueTriageProps {
  id: string;
  status: FindingTriageStatus;
}
