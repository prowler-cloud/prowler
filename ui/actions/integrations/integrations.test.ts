import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, revalidatePathMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  revalidatePathMock: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
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

import {
  revalidateIntegrationConnectionPages,
  testIntegrationConnection,
} from "./integrations";

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

  it("returns the task immediately for shared background tracking", async () => {
    // When
    const response = await testIntegrationConnection("jira-1");

    // Then
    expect(response).toEqual({
      success: true,
      message: "Connection test started. It may take some time to complete.",
      taskId: "task-1",
      data: { data: { id: "task-1", type: "tasks" } },
    });
  });

  it("revalidates every integration page through one shared action", async () => {
    // When
    await revalidateIntegrationConnectionPages();

    // Then
    expect(revalidatePathMock.mock.calls).toEqual([
      ["/integrations/amazon-s3"],
      ["/integrations/aws-security-hub"],
      ["/integrations/jira"],
      ["/integrations/slack"],
    ]);
  });
});
