import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, pollTaskUntilSettledMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  pollTaskUntilSettledMock: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: vi.fn().mockResolvedValue({ Authorization: "Bearer token" }),
  parseStringify: (value: unknown) => JSON.parse(JSON.stringify(value)),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: () => ({ error: "An error occurred" }),
  handleApiResponse: vi.fn(),
}));

vi.mock("@/actions/task/poll", () => ({
  pollTaskUntilSettled: pollTaskUntilSettledMock,
}));

import { testIntegrationConnection } from "./integrations";

describe("testIntegrationConnection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { id: "task-1", type: "tasks" } }), {
        status: 202,
      }),
    );
  });

  it("polls the connection task for up to 60 attempts, 3s apart", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: true,
      state: "completed",
      result: { connected: true, error: null },
    });

    // When
    const response = await testIntegrationConnection("jira-1");

    // Then
    expect(pollTaskUntilSettledMock).toHaveBeenCalledWith("task-1", {
      maxAttempts: 60,
      delayMs: 3000,
    });
    expect(response.success).toBe(true);
  });

  it("surfaces a poll timeout as a failed connection test", async () => {
    // Given
    pollTaskUntilSettledMock.mockResolvedValue({
      ok: false,
      error: "Task timeout",
    });

    // When
    const response = await testIntegrationConnection("jira-1");

    // Then
    expect(response).toEqual({ success: false, error: "Task timeout" });
  });
});
