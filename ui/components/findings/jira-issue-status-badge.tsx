import { Badge } from "@/components/shadcn/badge/badge";
import {
  JIRA_ISSUE_STATUS_CATEGORY,
  type JiraIssueLink,
  type JiraIssueStatusCategory,
} from "@/types/integrations";

type JiraIssueStatusVariant = "info" | "warning" | "success";

const CATEGORY_VARIANT: Record<
  JiraIssueStatusCategory,
  JiraIssueStatusVariant
> = {
  [JIRA_ISSUE_STATUS_CATEGORY.NEW]: "info",
  [JIRA_ISSUE_STATUS_CATEGORY.INDETERMINATE]: "warning",
  [JIRA_ISSUE_STATUS_CATEGORY.DONE]: "success",
} as const;

const CATEGORY_LABEL: Record<JiraIssueStatusCategory, string> = {
  [JIRA_ISSUE_STATUS_CATEGORY.NEW]: "To Do",
  [JIRA_ISSUE_STATUS_CATEGORY.INDETERMINATE]: "In Progress",
  [JIRA_ISSUE_STATUS_CATEGORY.DONE]: "Done",
} as const;

interface JiraIssueStatusBadgeProps {
  issue: Pick<JiraIssueLink, "issueStatus" | "issueStatusCategory">;
}

/**
 * Last status Prowler observed for a linked Jira issue. Falls back to the
 * category label when Jira's status name is unknown, and to a neutral badge
 * when neither was synced yet.
 */
export const JiraIssueStatusBadge = ({ issue }: JiraIssueStatusBadgeProps) => {
  const category = issue.issueStatusCategory;
  const label =
    issue.issueStatus || (category ? CATEGORY_LABEL[category] : "Unknown");
  const variant = category ? CATEGORY_VARIANT[category] : "tag";

  return (
    <Badge variant={variant} size="sm">
      {label}
    </Badge>
  );
};
