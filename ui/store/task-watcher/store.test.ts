import { beforeEach, describe, expect, it, vi } from "vitest";

const { pollMock } = vi.hoisted(() => ({
  pollMock: vi.fn(),
}));

vi.mock("@/actions/task/poll", () => ({
  pollTaskUntilSettled: pollMock,
}));

import {
  registerTaskKindHandler,
  resumePendingTasks,
  TASK_WATCHER_STATUS,
  trackAndPollTask,
  useTaskWatcherStore,
} from "./store";

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("task watcher store", () => {
  const onReady = vi.fn();
  const onError = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    useTaskWatcherStore.setState({ tasks: {} });
    registerTaskKindHandler("test-kind", { onReady, onError });
  });

  it("tracks a task, polls it to completion and fires onReady once", async () => {
    pollMock.mockResolvedValue({ ok: true, state: "completed" });

    await trackAndPollTask({
      taskId: "task-1",
      kind: "test-kind",
      meta: { complianceId: "csa_ccm_4.0" },
    });

    const task = useTaskWatcherStore.getState().tasks["task-1"];
    expect(task?.status).toBe(TASK_WATCHER_STATUS.READY);
    expect(onReady).toHaveBeenCalledTimes(1);
    expect(onReady.mock.calls[0][0].meta.complianceId).toBe("csa_ccm_4.0");
    expect(onError).not.toHaveBeenCalled();
  });

  it("marks the task as error when the backend task fails", async () => {
    pollMock.mockResolvedValue({ ok: true, state: "failed" });

    await trackAndPollTask({
      taskId: "task-2",
      kind: "test-kind",
      meta: {},
    });

    expect(useTaskWatcherStore.getState().tasks["task-2"]?.status).toBe(
      TASK_WATCHER_STATUS.ERROR,
    );
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onReady).not.toHaveBeenCalled();
  });

  it("settles the task as error when polling itself throws", async () => {
    pollMock.mockRejectedValue(new Error("network down"));

    await trackAndPollTask({ taskId: "task-7", kind: "test-kind", meta: {} });

    expect(useTaskWatcherStore.getState().tasks["task-7"]?.status).toBe(
      TASK_WATCHER_STATUS.ERROR,
    );
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onReady).not.toHaveBeenCalled();
  });

  it("keeps polling through transient timeouts until the ceiling", async () => {
    pollMock
      .mockResolvedValueOnce({ ok: false, error: "Task timeout" })
      .mockResolvedValueOnce({ ok: true, state: "completed" });

    await trackAndPollTask({ taskId: "task-3", kind: "test-kind", meta: {} });

    expect(pollMock).toHaveBeenCalledTimes(2);
    expect(useTaskWatcherStore.getState().tasks["task-3"]?.status).toBe(
      TASK_WATCHER_STATUS.READY,
    );
  });

  it("does not start a second poll loop for an already-pending task", async () => {
    let resolvePoll: (value: unknown) => void = () => {};
    pollMock.mockImplementation(
      () => new Promise((resolve) => (resolvePoll = resolve)),
    );

    const first = trackAndPollTask({
      taskId: "task-4",
      kind: "test-kind",
      meta: {},
    });
    const second = trackAndPollTask({
      taskId: "task-4",
      kind: "test-kind",
      meta: {},
    });

    resolvePoll({ ok: true, state: "completed" });
    await Promise.all([first, second]);
    await flush();

    expect(pollMock).toHaveBeenCalledTimes(1);
    expect(onReady).toHaveBeenCalledTimes(1);
  });

  it("resumes persisted pending tasks on watcher mount", async () => {
    pollMock.mockResolvedValue({ ok: true, state: "completed" });
    useTaskWatcherStore.setState({
      tasks: {
        "task-5": {
          taskId: "task-5",
          kind: "test-kind",
          status: TASK_WATCHER_STATUS.PENDING,
          meta: {},
          startedAt: Date.now(),
        },
      },
    });

    await resumePendingTasks();

    expect(useTaskWatcherStore.getState().tasks["task-5"]?.status).toBe(
      TASK_WATCHER_STATUS.READY,
    );
    expect(onReady).toHaveBeenCalledTimes(1);
  });

  it("expires stale persisted tasks instead of polling them", async () => {
    useTaskWatcherStore.setState({
      tasks: {
        "task-6": {
          taskId: "task-6",
          kind: "test-kind",
          status: TASK_WATCHER_STATUS.PENDING,
          meta: {},
          startedAt: Date.now() - 60 * 60 * 1000,
        },
      },
    });

    await resumePendingTasks();

    expect(pollMock).not.toHaveBeenCalled();
    expect(useTaskWatcherStore.getState().tasks["task-6"]?.status).toBe(
      TASK_WATCHER_STATUS.ERROR,
    );
    expect(onError).toHaveBeenCalledTimes(1);
  });
});
