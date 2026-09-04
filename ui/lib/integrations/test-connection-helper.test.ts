import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  revalidateIntegrationConnectionPagesMock,
  testIntegrationConnectionMock,
  trackAndPollTaskMock,
} = vi.hoisted(() => ({
  revalidateIntegrationConnectionPagesMock: vi.fn(),
  testIntegrationConnectionMock: vi.fn(),
  trackAndPollTaskMock: vi.fn(),
}));

vi.mock("@/actions/integrations", () => ({
  revalidateIntegrationConnectionPages:
    revalidateIntegrationConnectionPagesMock,
  testIntegrationConnection: testIntegrationConnectionMock,
}));

vi.mock("@/store/task-watcher/store", () => ({
  TASK_WATCHER_STATUS: { READY: "ready", ERROR: "error" },
  trackAndPollTask: trackAndPollTaskMock,
}));

import {
  executeIntegrationConnectionTest,
  runTestConnection,
} from "./test-connection-helper";

describe("integration connection test helper", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    revalidateIntegrationConnectionPagesMock.mockResolvedValue(undefined);
    testIntegrationConnectionMock.mockResolvedValue({
      success: true,
      taskId: "task-1",
    });
    trackAndPollTaskMock.mockResolvedValue({
      status: "ready",
      result: { connected: true, error: null },
    });
  });

  it("tracks a started test through the shared task watcher", async () => {
    // Given
    const onStarted = vi.fn();

    // When
    const result = await executeIntegrationConnectionTest("jira-1", onStarted);

    // Then
    expect(onStarted).toHaveBeenCalledOnce();
    expect(trackAndPollTaskMock).toHaveBeenCalledWith({
      taskId: "task-1",
      kind: "integration-connection-test",
      meta: { integrationId: "jira-1" },
      notifyHandler: false,
    });
    expect(revalidateIntegrationConnectionPagesMock).toHaveBeenCalledOnce();
    expect(result).toEqual({
      success: true,
      message: "Connection test completed successfully.",
    });
  });

  it("preserves the backend connection failure details", async () => {
    // Given
    trackAndPollTaskMock.mockResolvedValue({
      status: "ready",
      result: {
        connected: false,
        error: "Channel unavailable",
        channel: "C123",
      },
    });

    // When
    const result = await executeIntegrationConnectionTest("slack-1");

    // Then
    expect(result).toEqual({
      success: false,
      error: "Channel unavailable",
      failedChannelId: "C123",
    });
  });

  it("surfaces task watcher failures", async () => {
    // Given
    trackAndPollTaskMock.mockResolvedValue({
      status: "error",
      error: "The task is taking too long. Try again later.",
    });

    // When
    const result = await executeIntegrationConnectionTest("jira-1");

    // Then
    expect(result).toEqual({
      success: false,
      error: "The task is taking too long. Try again later.",
    });
  });

  it("completes once when the task cannot be started", async () => {
    // Given
    const onComplete = vi.fn();
    const onError = vi.fn();
    testIntegrationConnectionMock.mockResolvedValue({
      success: false,
      error: "Could not start",
    });

    // When
    await runTestConnection({
      integrationId: "jira-1",
      integrationType: "jira",
      onComplete,
      onError,
    });

    // Then
    expect(onError).toHaveBeenCalledWith("Could not start");
    expect(onComplete).toHaveBeenCalledOnce();
  });
});
