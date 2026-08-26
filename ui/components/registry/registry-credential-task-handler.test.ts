import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WatchedTask } from "@/store/task-watcher/store";

import { registryCredentialTaskHandler } from "./registry-credential-task-handler";

const { refreshRegistryCredentialMock, toastMock } = vi.hoisted(() => ({
  refreshRegistryCredentialMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/registry/registry", () => ({
  refreshRegistryCredential: refreshRegistryCredentialMock,
}));

vi.mock("@/components/shadcn/toast", () => ({ toast: toastMock }));

const buildTask = (overrides: Partial<WatchedTask> = {}): WatchedTask => ({
  taskId: "task-1",
  kind: "registry-credential-validation",
  status: "ready",
  startedAt: Date.now(),
  meta: {},
  ...overrides,
});

describe("registryCredentialTaskHandler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("announces the connected Registry after a resumed task completes validly", async () => {
    // Given
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: {
        configured: true,
        isValid: true,
        scopes: ["catalog:read"],
        validationPending: false,
      },
    });

    // When
    registryCredentialTaskHandler.onReady(buildTask());

    // Then
    await vi.waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({ title: "Registry connected" }),
    );
  });

  it("reports an invalid key after a resumed task completes without an active credential", async () => {
    // Given
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: {
        configured: false,
        isValid: false,
        scopes: [],
        validationPending: false,
      },
    });

    // When
    registryCredentialTaskHandler.onReady(buildTask());

    // Then
    await vi.waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        variant: "destructive",
        title: "Registry key validation failed",
        description:
          "The submitted Registry key could not be validated. Connect a new key from the Registry page.",
      }),
    );
  });

  it("reports a failure when the authoritative credential read fails", async () => {
    // Given
    refreshRegistryCredentialMock.mockResolvedValue({ status: "error" });

    // When
    registryCredentialTaskHandler.onReady(buildTask());

    // Then
    await vi.waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Registry key validation failed",
        }),
      ),
    );
  });

  it("reports the watcher error when a resumed task settles in error", () => {
    // When
    registryCredentialTaskHandler.onError(
      buildTask({ status: "error", error: 'Task ended in state "failed".' }),
    );

    // Then
    expect(toastMock).toHaveBeenCalledWith({
      variant: "destructive",
      title: "Registry key validation failed",
      description: 'Task ended in state "failed".',
    });
    expect(refreshRegistryCredentialMock).not.toHaveBeenCalled();
  });
});
