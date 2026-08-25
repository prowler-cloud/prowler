import {
  JIRA_ISSUE_STATUS_CATEGORY,
  type JiraIssueLink,
  type JiraIssueStatusCategory,
} from "@/types/integrations";

import type { JiraIssuesResponse } from "./jira-issues.types";

const STATUS_CATEGORIES: readonly string[] = Object.values(
  JIRA_ISSUE_STATUS_CATEGORY,
);

const toStatusCategory = (value: unknown): JiraIssueStatusCategory | null =>
  typeof value === "string" && STATUS_CATEGORIES.includes(value)
    ? (value as JiraIssueStatusCategory)
    : null;

export const adaptJiraIssues = (
  response: JiraIssuesResponse | undefined,
): JiraIssueLink[] => {
  const data = Array.isArray(response?.data) ? response.data : [];

  return data.flatMap((resource) => {
    const attributes = resource.attributes;
    // A row without a key is a reservation still being created; the API hides
    // them, but never render one if it slips through.
    if (!attributes?.issue_key) return [];

    return [
      {
        id: resource.id,
        findingUid: attributes.finding_uid,
        findingId: attributes.finding_id,
        issueKey: attributes.issue_key,
        issueUrl: attributes.issue_url || null,
        projectKey: attributes.project_key,
        issueStatus: attributes.issue_status || null,
        issueStatusCategory: toStatusCategory(attributes.issue_status_category),
        statusSyncedAt: attributes.status_synced_at ?? null,
        insertedAt: attributes.inserted_at,
        providerId: resource.relationships?.provider?.data?.id ?? null,
        integrationId: resource.relationships?.integration?.data?.id ?? null,
      },
    ];
  });
};
