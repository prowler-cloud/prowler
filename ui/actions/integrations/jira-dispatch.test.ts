import { beforeEach, describe, expect, it, vi } from "vitest";

const { pollTaskUntilSettledMock } = vi.hoisted(() => ({
  pollTaskUntilSettledMock: vi.fn(),
}));

vi.mock("@/actions/task/poll", () => ({
  pollTaskUntilSettled: pollTaskUntilSettledMock,
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: vi.fn(),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: vi.fn(),
}));

import { pollJiraDispatchTask } from "./jira-dispatch";

describe("pollJiraDispatchTask", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return the backend error when a completed task has failed Jira dispatches", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: {
        created_count: 0,
        failed_count: 1,
        error: "Jira project requires custom fields: Team is required",
      },
    });

    // When
    const result = await pollJiraDispatchTask("task-123");

    // Then
    expect(result).toEqual({
      success: false,
      error: "Jira project requires custom fields: Team is required",
    });
  });

  it("should return a fallback error when a completed task has failures without an error", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: {
        created_count: 0,
        failed_count: 1,
      },
    });

    // When
    const result = await pollJiraDispatchTask("task-123");

    // Then
    expect(result).toEqual({
      success: false,
      error: "Failed to create Jira issue.",
    });
  });

  it("should return a plural fallback error when a completed task has multiple failures without an error", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: {
        created_count: 0,
        failed_count: 3,
      },
    });

    // When
    const result = await pollJiraDispatchTask("task-123");

    // Then
    expect(result).toEqual({
      success: false,
      error: "Failed to create 3 Jira issues.",
    });
  });

  it("should surface task failure result errors", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "failed",
      result: {
        error: "Jira credentials are invalid.",
      },
    });

    // When
    const result = await pollJiraDispatchTask("task-123");

    // Then
    expect(result).toEqual({
      success: false,
      error: "Jira credentials are invalid.",
    });
  });

  it("should return success when a completed task has no failures", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: {
        created_count: 1,
        failed_count: 0,
      },
    });

    // When
    const result = await pollJiraDispatchTask("task-123");

    // Then
    expect(result).toEqual({
      success: true,
      message: "Finding successfully sent to Jira!",
    });
  });
});
