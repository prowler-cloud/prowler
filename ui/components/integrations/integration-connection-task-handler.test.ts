import { beforeEach, describe, expect, it, vi } from "vitest";

const { revalidateIntegrationConnectionPagesMock, toastMock } = vi.hoisted(
  () => ({
    revalidateIntegrationConnectionPagesMock: vi.fn(),
    toastMock: vi.fn(),
  }),
);

vi.mock("@/actions/integrations", () => ({
  revalidateIntegrationConnectionPages:
    revalidateIntegrationConnectionPagesMock,
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: toastMock,
}));

import { integrationConnectionTaskHandler } from "./integration-connection-task-handler";

const task = {
  taskId: "task-1",
  kind: "integration-connection-test",
  status: "ready" as const,
  meta: { integrationId: "jira-1" },
  startedAt: 1,
};

describe("integration connection task handler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    revalidateIntegrationConnectionPagesMock.mockResolvedValue(undefined);
  });

  it("revalidates integrations and reports a resumed success", () => {
    // When
    integrationConnectionTaskHandler.onReady({
      ...task,
      result: { connected: true, error: null },
    });

    // Then
    expect(revalidateIntegrationConnectionPagesMock).toHaveBeenCalledOnce();
    expect(toastMock).toHaveBeenCalledWith({
      title: "Connection test successful!",
      description: "Connection test completed successfully.",
    });
  });

  it("reports a resumed backend failure", () => {
    // When
    integrationConnectionTaskHandler.onReady({
      ...task,
      result: { connected: false, error: "Missing permission" },
    });

    // Then
    expect(toastMock).toHaveBeenCalledWith({
      variant: "destructive",
      title: "Connection test failed",
      description: "Missing permission",
    });
  });
});
