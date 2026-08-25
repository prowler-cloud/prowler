import { describe, expect, it } from "vitest";

import { adaptJiraIssues } from "./jira-issues.adapter";

describe("adaptJiraIssues", () => {
  it("returns an empty list for a missing or malformed document", () => {
    expect(adaptJiraIssues(undefined)).toEqual([]);
    expect(adaptJiraIssues({})).toEqual([]);
    expect(adaptJiraIssues({ data: undefined })).toEqual([]);
  });

  it("maps attributes and relationships to the domain shape", () => {
    const [link] = adaptJiraIssues({
      data: [
        {
          type: "jira-issues",
          id: "link-1",
          attributes: {
            inserted_at: "2026-08-25T10:00:00Z",
            updated_at: "2026-08-25T10:00:00Z",
            finding_uid: "uid-1",
            finding_id: "finding-1",
            issue_key: "SEC-1",
            issue_id: "10001",
            issue_url: "",
            project_key: "SEC",
            issue_status: "",
            issue_status_category: "done",
            status_synced_at: null,
          },
          relationships: { provider: { data: null } },
        },
      ],
    });

    expect(link).toEqual({
      id: "link-1",
      findingUid: "uid-1",
      findingId: "finding-1",
      issueKey: "SEC-1",
      issueUrl: null,
      projectKey: "SEC",
      issueStatus: null,
      issueStatusCategory: "done",
      statusSyncedAt: null,
      insertedAt: "2026-08-25T10:00:00Z",
      providerId: null,
      integrationId: null,
    });
  });
});
