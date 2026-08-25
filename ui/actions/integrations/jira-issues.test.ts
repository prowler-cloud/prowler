import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

import { getJiraIssuesForFindings } from "./jira-issues";

const PROVIDER_ID = "0f6d1c0e-8a2c-4f0e-9b0e-4c1a2b3c4d5e";

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/vnd.api+json" },
  });

const issue = (attributes: Record<string, unknown> = {}) => ({
  type: "jira-issues",
  id: "link-1",
  attributes: {
    inserted_at: "2026-08-25T10:00:00Z",
    updated_at: "2026-08-25T10:00:00Z",
    finding_uid: "prowler-aws-check-1",
    finding_id: "finding-1",
    issue_key: "SEC-1",
    issue_id: "10001",
    issue_url: "https://acme.atlassian.net/browse/SEC-1",
    project_key: "SEC",
    issue_status: "To Do",
    issue_status_category: "new",
    status_synced_at: "2026-08-25T10:00:05Z",
    ...attributes,
  },
  relationships: {
    provider: { data: { type: "providers", id: PROVIDER_ID } },
    integration: { data: { type: "integrations", id: "integration-1" } },
  },
});

const lastFetchUrl = (): URL => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  return new URL(String(call[0]));
};

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockResolvedValue(jsonResponse({ data: [] }));
  getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("getJiraIssuesForFindings", () => {
  it("returns nothing without fetching for an empty query", async () => {
    // When
    const result = await getJiraIssuesForFindings({ findingUids: [] });

    // Then
    expect(result).toEqual({ issues: [], unavailable: false });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("filters by finding uid and provider, deduplicating uids", async () => {
    // Given
    fetchMock.mockResolvedValue(jsonResponse({ data: [issue()] }));

    // When
    const result = await getJiraIssuesForFindings({
      findingUids: ["prowler-aws-check-1", "prowler-aws-check-1", "other"],
      providerId: PROVIDER_ID,
    });

    // Then
    const url = lastFetchUrl();
    expect(url.pathname).toBe("/api/v1/jira-issues");
    expect(url.searchParams.get("filter[finding_uid__in]")).toBe(
      "prowler-aws-check-1,other",
    );
    expect(url.searchParams.get("filter[provider_id]")).toBe(PROVIDER_ID);
    expect(url.searchParams.get("page[size]")).toBe("2");
    expect(result.unavailable).toBe(false);
    expect(result.issues).toEqual([
      {
        id: "link-1",
        findingUid: "prowler-aws-check-1",
        findingId: "finding-1",
        issueKey: "SEC-1",
        issueUrl: "https://acme.atlassian.net/browse/SEC-1",
        projectKey: "SEC",
        issueStatus: "To Do",
        issueStatusCategory: "new",
        statusSyncedAt: "2026-08-25T10:00:05Z",
        insertedAt: "2026-08-25T10:00:00Z",
        providerId: PROVIDER_ID,
        integrationId: "integration-1",
      },
    ]);
  });

  it("degrades to unavailable when the endpoint does not exist", async () => {
    // Given
    fetchMock.mockResolvedValue(jsonResponse({ errors: [] }, 404));

    // When
    const result = await getJiraIssuesForFindings({ findingUids: ["uid"] });

    // Then
    expect(result).toEqual({ issues: [], unavailable: true });
  });

  it("degrades to unavailable on a network error", async () => {
    // Given
    fetchMock.mockRejectedValue(new Error("boom"));

    // When
    const result = await getJiraIssuesForFindings({ findingUids: ["uid"] });

    // Then
    expect(result).toEqual({ issues: [], unavailable: true });
  });

  it("ignores rows without an issue key and unknown status categories", async () => {
    // Given
    fetchMock.mockResolvedValue(
      jsonResponse({
        data: [
          issue({ issue_key: "" }),
          issue({ issue_status_category: "weird", issue_url: "" }),
        ],
      }),
    );

    // When
    const result = await getJiraIssuesForFindings({ findingUids: ["uid"] });

    // Then
    expect(result.issues).toHaveLength(1);
    expect(result.issues[0].issueStatusCategory).toBeNull();
    expect(result.issues[0].issueUrl).toBeNull();
  });
});
