import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WatchedTask } from "@/store/task-watcher/store";

import { registryCredentialTaskHandler } from "./registry-credential-task-handler";

const {
  refreshRegistryCollectionsMock,
  refreshRegistryCredentialMock,
  toastMock,
} = vi.hoisted(() => ({
  refreshRegistryCollectionsMock: vi.fn(),
  refreshRegistryCredentialMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/registry/registry", () => ({
  refreshRegistryCollections: refreshRegistryCollectionsMock,
  refreshRegistryCredential: refreshRegistryCredentialMock,
}));

vi.mock("@/store/task-watcher/store", () => ({
  TASK_WATCHER_STATUS: { PENDING: "pending", READY: "ready", ERROR: "error" },
}));

vi.mock("@/components/shadcn/toast", () => ({ toast: toastMock }));

const buildTask = (overrides: Partial<WatchedTask> = {}): WatchedTask => ({
  taskId: "task-1",
  kind: "registry-credential-validation",
  status: "ready",
  startedAt: Date.now(),
  meta: {},
  result: { stored: true, error: null },
  ...overrides,
});

describe("registryCredentialTaskHandler", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    refreshRegistryCollectionsMock.mockResolvedValue({
      status: "complete",
      catalog: { status: "complete", artifacts: [] },
      tenantArtifacts: [],
    });
    refreshRegistryCredentialMock.mockResolvedValue({ status: "error" });
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
        description: "This Registry key is invalid. Check it and try again.",
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

  it("reports a safe failure when a resumed task settles in error", async () => {
    // When
    await registryCredentialTaskHandler.onError(
      buildTask({ status: "error", error: 'Task ended in state "failed".' }),
    );

    // Then
    expect(toastMock).toHaveBeenCalledWith({
      variant: "destructive",
      title: "Registry key validation failed",
      description: "Registry key validation could not be completed. Try again.",
    });
    expect(refreshRegistryCredentialMock).toHaveBeenCalledTimes(1);
  });
  it("does not announce a rejected replacement as connected", async () => {
    const refresh = vi.fn();
    window.addEventListener("registry-credential-changed", refresh);
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: {
        configured: true,
        isValid: true,
        scopes: [],
        validationPending: false,
      },
    });
    await registryCredentialTaskHandler.onReady(
      buildTask({ result: { stored: false, error: "Invalid key" } }),
    );
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive" }),
    );
    expect(refresh).toHaveBeenCalledOnce();
    window.removeEventListener("registry-credential-changed", refresh);
  });
});
