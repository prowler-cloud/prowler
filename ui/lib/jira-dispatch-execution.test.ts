import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  JIRA_DISPATCH_MODE,
  type JiraDispatchTargetBatch,
} from "@/types/integrations";

import { executeJiraDispatchBatches } from "./jira-dispatch-execution";

const { sendJiraDispatchMock, trackAndPollTaskMock } = vi.hoisted(() => ({
  sendJiraDispatchMock: vi.fn(),
  trackAndPollTaskMock: vi.fn(),
}));

vi.mock("@/actions/integrations/jira-dispatch", () => ({
  sendJiraDispatch: sendJiraDispatchMock,
}));

vi.mock("@/store/task-watcher/store", () => ({
  TASK_WATCHER_STATUS: { READY: "ready" },
  trackAndPollTask: trackAndPollTaskMock,
}));

const settings = {
  integrationId: "jira-1",
  projectKey: "SEC",
  issueType: "Task",
  dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
};

describe("executeJiraDispatchBatches", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sendJiraDispatchMock.mockResolvedValue({
      success: true,
      taskId: "task-1",
      message: "Started",
    });
    trackAndPollTaskMock.mockResolvedValue({
      status: "ready",
      result: { created_count: 2, failed_count: 0 },
    });
  });

  it("uses one dispatch path and aggregates successful batches", async () => {
    // Given
    const batches: JiraDispatchTargetBatch[] = [
      {
        targetIds: ["check-a"],
        targetType: "check_id" as const,
        dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
      },
      {
        targetIds: ["finding-a"],
        targetType: "finding_id" as const,
        dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
      },
    ];

    // When
    const result = await executeJiraDispatchBatches(batches, settings);

    // Then
    expect(sendJiraDispatchMock).toHaveBeenCalledTimes(2);
    expect(sendJiraDispatchMock).toHaveBeenNthCalledWith(2, {
      integrationId: "jira-1",
      targetIds: ["finding-a"],
      filter: "finding_id",
      projectKey: "SEC",
      issueType: "Task",
      dispatchMode: "individual",
    });
    expect(result).toMatchObject({
      startedTaskCount: 2,
      successfulTaskCount: 2,
      successfulIssueCount: 4,
      successMessage: "4 Jira issues were created or updated successfully.",
      errors: [],
      warnings: [],
    });
  });

  it("returns only failed finding IDs as an individual retry batch", async () => {
    // Given
    trackAndPollTaskMock.mockResolvedValue({
      status: "ready",
      result: {
        created_count: 1,
        failed_count: 2,
        failed_finding_ids: ["finding-b", "finding-b", "finding-c"],
        error: "Two issues failed.",
      },
    });

    // When
    const result = await executeJiraDispatchBatches(
      [
        {
          targetIds: ["check-a"],
          targetType: "check_id",
          dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
        },
      ],
      settings,
    );

    // Then
    expect(result.retryBatch).toEqual({
      targetIds: ["finding-b", "finding-c"],
      targetType: "finding_id",
      dispatchMode: "individual",
    });
    expect(result.warnings).toEqual([
      "Two issues failed. Jira dispatch completed with 3 failed and 1 created/updated issue.",
    ]);
  });

  it("does not offer an automatic retry after an unknown launch failure", async () => {
    // Given
    sendJiraDispatchMock.mockRejectedValue(new Error("Connection closed"));

    // When
    const result = await executeJiraDispatchBatches(
      [
        {
          targetIds: ["finding-a"],
          targetType: "finding_id",
          dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
        },
      ],
      settings,
    );

    // Then
    expect(result.startedTaskCount).toBe(0);
    expect(result.retryBatch).toBeUndefined();
    expect(result.errors).toEqual([
      "The Jira dispatch status is unknown after a connection error. Check Jira before retrying.",
    ]);
  });
});
