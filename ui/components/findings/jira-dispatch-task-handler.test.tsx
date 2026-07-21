import { type ComponentProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WatchedTask } from "@/store/task-watcher/store";
import { JIRA_DISPATCH_MODE } from "@/types/integrations";

import { jiraDispatchTaskHandler } from "./jira-dispatch-task-handler";

interface ToastActionMockProps extends ComponentProps<"button"> {
  altText: string;
}

const { sendJiraDispatchMock, toastMock, trackAndPollTaskMock } = vi.hoisted(
  () => ({
    sendJiraDispatchMock: vi.fn(),
    toastMock: vi.fn(),
    trackAndPollTaskMock: vi.fn(),
  }),
);

vi.mock("@/actions/integrations/jira-dispatch", () => ({
  sendJiraDispatch: sendJiraDispatchMock,
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: toastMock,
  ToastAction: ({
    altText: _altText,
    children,
    ...props
  }: ToastActionMockProps) => <button {...props}>{children}</button>,
}));

vi.mock("@/store/task-watcher/store", () => ({
  trackAndPollTask: trackAndPollTaskMock,
}));

const buildTask = (result: unknown): WatchedTask => ({
  taskId: "task-1",
  kind: "jira-dispatch",
  status: "ready",
  startedAt: Date.now(),
  meta: {
    integrationId: "jira-1",
    projectKey: "SEC",
    issueType: "Task",
    dispatchMode: JIRA_DISPATCH_MODE.GROUPED,
  },
  result,
});

describe("jiraDispatchTaskHandler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sendJiraDispatchMock.mockResolvedValue({
      success: true,
      taskId: "retry-task",
      message: "Started",
    });
  });

  it("shows the completed Jira result after a persisted task resumes", () => {
    // Given
    const task = buildTask({ created_count: 2, failed_count: 0 });

    // When
    jiraDispatchTaskHandler.onReady(task);

    // Then
    expect(toastMock).toHaveBeenCalledWith({
      title: "Success!",
      description: "2 Jira issues were created or updated successfully.",
    });
  });

  it("retries only failed Findings from a resumed partial task", async () => {
    // Given
    const task = buildTask({
      created_count: 1,
      failed_count: 2,
      failed_finding_ids: ["finding-2", "finding-3"],
      error: "Two Jira issues failed.",
    });
    jiraDispatchTaskHandler.onReady(task);
    const partialToast = toastMock.mock.calls.at(-1)?.[0];

    // When
    await partialToast.action.props.onClick();

    // Then
    expect(sendJiraDispatchMock).toHaveBeenCalledWith({
      integrationId: "jira-1",
      targetIds: ["finding-2", "finding-3"],
      filter: "finding_id",
      projectKey: "SEC",
      issueType: "Task",
      dispatchMode: "individual",
    });
    expect(trackAndPollTaskMock).toHaveBeenCalledWith({
      taskId: "retry-task",
      kind: "jira-dispatch",
      meta: {
        ...task.meta,
        dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
      },
    });
  });

  it("surfaces task watcher errors without offering an unsafe retry", () => {
    // Given
    const task = {
      ...buildTask(undefined),
      status: "error",
      error: "Tracking the task failed unexpectedly. Try again later.",
    } as WatchedTask;

    // When
    jiraDispatchTaskHandler.onError(task);

    // Then
    expect(toastMock).toHaveBeenCalledWith({
      variant: "destructive",
      title: "Jira dispatch failed",
      description: "Tracking the task failed unexpectedly. Try again later.",
    });
  });
});
