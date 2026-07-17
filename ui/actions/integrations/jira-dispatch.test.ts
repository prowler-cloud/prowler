import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, pollTaskUntilSettledMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  pollTaskUntilSettledMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: vi.fn().mockResolvedValue({ Authorization: "Bearer token" }),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: () => ({ error: "An error occurred" }),
}));

vi.mock("@/actions/task/poll", () => ({
  pollTaskUntilSettled: pollTaskUntilSettledMock,
}));

import { pollJiraDispatchTask, sendJiraDispatch } from "./jira-dispatch";

describe("sendJiraDispatch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            id: "task-1",
            type: "tasks",
            attributes: { result: null },
          },
        }),
        { status: 202 },
      ),
    );
  });

  it("should send grouped dispatch mode with multiple finding IDs", async () => {
    // Given / When
    await sendJiraDispatch({
      integrationId: "jira-1",
      targetIds: ["finding-1", "finding-2"],
      filter: "finding_id",
      projectKey: "SEC",
      issueType: "Task",
      dispatchMode: "grouped",
    });

    // Then
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      "https://api.example.com/api/v1/integrations/jira-1/jira/dispatches?filter%5Bfinding_id__in%5D=finding-1%2Cfinding-2",
    );
    expect(JSON.parse(init.body as string)).toMatchObject({
      data: {
        attributes: {
          dispatch_mode: "grouped",
          issue_type: "Task",
          project_key: "SEC",
        },
      },
    });
  });

  it("should send grouped dispatch mode with a finding group check ID", async () => {
    // Given / When
    await sendJiraDispatch({
      integrationId: "jira-1",
      targetIds: ["s3_bucket_public_access"],
      filter: "check_id",
      projectKey: "SEC",
      issueType: "Task",
      dispatchMode: "grouped",
    });

    // Then
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      "https://api.example.com/api/v1/integrations/jira-1/jira/dispatches?filter%5Bcheck_id%5D=s3_bucket_public_access",
    );
    expect(JSON.parse(init.body as string)).toMatchObject({
      data: { attributes: { dispatch_mode: "grouped" } },
    });
  });

  it("should preserve partial success when Jira dispatch has created and failed issues", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: { created_count: 2, failed_count: 1 },
    });

    // When
    const result = await pollJiraDispatchTask("task-1");

    // Then
    expect(result).toEqual({
      success: true,
      message: "2 Jira issues were created or updated successfully.",
      warning:
        "Jira dispatch completed with 1 failed and 2 created/updated issues.",
    });
  });

  it("should include updated issues in partial failure summaries", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: { created_count: 0, updated_count: 2, failed_count: 1 },
    });

    // When
    const result = await pollJiraDispatchTask("task-1");

    // Then
    expect(result).toEqual({
      success: true,
      message: "2 Jira issues were created or updated successfully.",
      warning:
        "Jira dispatch completed with 1 failed and 2 created/updated issues.",
    });
  });

  it("should fail completed task polling when grouped dispatch reports failed groups", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: { created_count: 1, failed_groups: [{ check_id: "check-a" }] },
    });

    // When
    const result = await pollJiraDispatchTask("task-1");

    // Then
    expect(result).toEqual({
      success: true,
      message: "Finding successfully sent to Jira!",
      warning:
        "Jira dispatch completed with 1 failed and 1 created/updated issue.",
    });
  });

  it("should succeed completed task polling when grouped dispatch reports no failed groups", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: { created_count: 1, failed_groups: [] },
    });

    // When
    const result = await pollJiraDispatchTask("task-1");

    // Then
    expect(result).toEqual({
      success: true,
      message: "Finding successfully sent to Jira!",
    });
  });

  it("should succeed completed task polling with grouped created and updated issue result shape", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: {
        created_count: 1,
        updated_count: 1,
        failed_count: 0,
        created_issues: [{ key: "SEC-1" }],
        updated_issues: [{ key: "SEC-2" }],
        failed_groups: [],
      },
    });

    // When
    const result = await pollJiraDispatchTask("task-1");

    // Then
    expect(pollTaskUntilSettledMock).toHaveBeenCalledWith("task-1", {
      maxAttempts: 5,
      delayMs: 2000,
    });
    expect(result).toEqual({
      success: true,
      message: "Finding successfully sent to Jira!",
    });
  });

  it("should fail completed task polling when Jira dispatch completed as a no-op", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: { created_count: 0, updated_count: 0, failed_count: 0 },
    });

    // When
    const result = await pollJiraDispatchTask("task-1");

    // Then
    expect(result).toEqual({
      success: false,
      error: "Jira dispatch completed but did not create or update any issues.",
    });
  });

  it("should fail completed task polling when Jira dispatch has no result payload", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: null,
    });

    // When
    const result = await pollJiraDispatchTask("task-1");

    // Then
    expect(result).toEqual({
      success: false,
      error: "Jira dispatch completed but did not create or update any issues.",
    });
  });
});
