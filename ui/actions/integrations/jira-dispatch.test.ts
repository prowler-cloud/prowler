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

  it("should fail completed task polling when Jira dispatch has partial failures", async () => {
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
      success: false,
      error: "Jira dispatch completed with 1 failed and 2 created issues.",
    });
  });
});
