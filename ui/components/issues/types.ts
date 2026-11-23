import type { FindingTriageStatus } from "@/types/findings-triage";
import type { IssueFinding } from "@/types/issues";

export interface IssueFindingsProps {
  /** One entry per finding, with a resource to open in the group drill-down. */
  findings: IssueFinding[];
  /** All the findings the issue folds; the list shows a bounded preview. */
  total: number;
  onOpenFinding: (findingId: string) => void;
}

export interface IssueTriageProps {
  id: string;
  status: FindingTriageStatus;
}
