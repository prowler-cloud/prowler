import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getTaskMock } = vi.hoisted(() => ({
  getTaskMock: vi.fn(),
}));

vi.mock("@/actions/task/tasks", () => ({
  getTask: getTaskMock,
}));

vi.mock("@/lib/sentry-breadcrumbs", () => ({
  addTaskEvent: vi.fn(),
}));

import { pollTaskUntilSettled } from "./poll";

const executing = { data: { attributes: { state: "executing" } } };
const completed = {
  data: { attributes: { state: "completed", result: { connected: true } } },
};

describe("pollTaskUntilSettled", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps polling past 20 attempts when the bound allows it", async () => {
    // Given: the task stays executing for 30 polls, then completes
    let calls = 0;
    getTaskMock.mockImplementation(async () =>
      ++calls <= 30 ? executing : completed,
    );

    // When
    const pending = pollTaskUntilSettled("task-1", {
      maxAttempts: 60,
      delayMs: 3000,
    });
    await vi.runAllTimersAsync();
    const settled = await pending;

    // Then
    expect(settled).toMatchObject({
      ok: true,
      state: "completed",
      result: { connected: true },
    });
    expect(getTaskMock).toHaveBeenCalledTimes(31);
  });

  it("times out only after maxAttempts polls", async () => {
    // Given
    getTaskMock.mockResolvedValue(executing);

    // When
    const pending = pollTaskUntilSettled("task-1", {
      maxAttempts: 60,
      delayMs: 3000,
    });
    await vi.runAllTimersAsync();

    // Then
    await expect(pending).resolves.toEqual({
      ok: false,
      error: "Task timeout",
    });
    expect(getTaskMock).toHaveBeenCalledTimes(60);
  });
});
