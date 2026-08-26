import { beforeEach, describe, expect, it, vi } from "vitest";

import type { RegistryCredentialStatus } from "@/types/registry";

import { executeRegistryCredentialValidation } from "./registry-credential-execution";
import { REGISTRY_CREDENTIAL_TASK_KIND } from "./registry-credential-task";

const {
  refreshRegistryCredentialMock,
  submitRegistryCredentialMock,
  trackAndPollTaskMock,
} = vi.hoisted(() => ({
  refreshRegistryCredentialMock: vi.fn(),
  submitRegistryCredentialMock: vi.fn(),
  trackAndPollTaskMock: vi.fn(),
}));

vi.mock("@/actions/registry/registry", () => ({
  refreshRegistryCredential: refreshRegistryCredentialMock,
  submitRegistryCredential: submitRegistryCredentialMock,
}));

vi.mock("@/store/task-watcher/store", () => ({
  TASK_WATCHER_STATUS: { PENDING: "pending", READY: "ready", ERROR: "error" },
  trackAndPollTask: trackAndPollTaskMock,
}));

const activeCredential: RegistryCredentialStatus = {
  configured: true,
  isValid: true,
  scopes: ["catalog:read"],
  validationPending: false,
};
const noCredential: RegistryCredentialStatus = {
  configured: false,
  isValid: false,
  scopes: [],
  validationPending: false,
};
const pendingCredential: RegistryCredentialStatus = {
  configured: true,
  isValid: false,
  scopes: [],
  validationPending: true,
};

describe("executeRegistryCredentialValidation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    submitRegistryCredentialMock.mockResolvedValue({
      status: "submitted",
      taskId: "task-1",
      priorConfigured: false,
    });
    trackAndPollTaskMock.mockResolvedValue({ status: "ready" });
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: activeCredential,
    });
  });

  it("connects after the watched task settles and the credential is active", async () => {
    // Given
    const key = "registry-test-key";

    // When
    const outcome = await executeRegistryCredentialValidation(key);

    // Then
    expect(outcome).toEqual({
      status: "connected",
      credential: activeCredential,
    });
    expect(submitRegistryCredentialMock).toHaveBeenCalledWith(key);
    expect(trackAndPollTaskMock).toHaveBeenCalledWith({
      taskId: "task-1",
      kind: REGISTRY_CREDENTIAL_TASK_KIND,
      meta: {},
      notifyHandler: false,
    });
    // The key must never reach the persisted watcher record.
    expect(JSON.stringify(trackAndPollTaskMock.mock.calls)).not.toContain(key);
  });

  it("reports an invalid key when the settled credential is not active", async () => {
    // Given
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: noCredential,
    });

    // When
    const outcome = await executeRegistryCredentialValidation("bad-key");

    // Then
    expect(outcome).toEqual({ status: "invalid", credential: noCredential });
  });

  it("keeps a failed replacement distinct from a first invalid key", async () => {
    // Given
    submitRegistryCredentialMock.mockResolvedValue({
      status: "submitted",
      taskId: "task-2",
      priorConfigured: true,
    });
    trackAndPollTaskMock.mockResolvedValue({
      status: "error",
      error: 'Task ended in state "failed".',
    });
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: activeCredential,
    });

    // When
    const outcome = await executeRegistryCredentialValidation("replacement");

    // Then
    expect(outcome).toEqual({ status: "replacement_failed" });
  });

  it("reports a validation still pending after the watch settles", async () => {
    // Given
    trackAndPollTaskMock.mockResolvedValue({
      status: "error",
      error: "The task expired before it could be tracked to completion.",
    });
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: pendingCredential,
    });

    // When
    const outcome = await executeRegistryCredentialValidation("slow-key");

    // Then
    expect(outcome).toEqual({
      status: "pending",
      credential: pendingCredential,
    });
  });

  it("passes submit failures through without watching any task", async () => {
    // Given
    submitRegistryCredentialMock
      .mockResolvedValueOnce({ status: "access_denied" })
      .mockResolvedValueOnce({
        status: "replacement_failed",
        credential: activeCredential,
      })
      .mockResolvedValueOnce({ status: "error" });

    // When
    const denied = await executeRegistryCredentialValidation("key");
    const replacementFailed = await executeRegistryCredentialValidation("key");
    const failed = await executeRegistryCredentialValidation("key");

    // Then
    expect(denied).toEqual({ status: "access_denied" });
    expect(replacementFailed).toEqual({ status: "replacement_failed" });
    expect(failed).toEqual({ status: "error" });
    expect(trackAndPollTaskMock).not.toHaveBeenCalled();
    expect(refreshRegistryCredentialMock).not.toHaveBeenCalled();
  });

  it("bounds the watch and reports the still-pending validation at the deadline", async () => {
    // Given: the validation task never settles (e.g. no worker consumes it)
    vi.useFakeTimers();
    try {
      trackAndPollTaskMock.mockReturnValue(new Promise(() => {}));
      refreshRegistryCredentialMock.mockResolvedValue({
        status: "status",
        credential: pendingCredential,
      });

      // When
      const outcomePromise = executeRegistryCredentialValidation("stuck-key");
      await vi.advanceTimersByTimeAsync(30_000);

      // Then: the caller regains control instead of waiting on the watcher
      await expect(outcomePromise).resolves.toEqual({
        status: "pending",
        credential: pendingCredential,
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps an unsettled replacement pending instead of condemning it", async () => {
    // Given: the watch gave up while the prior key is still the active one
    submitRegistryCredentialMock.mockResolvedValue({
      status: "submitted",
      taskId: "task-3",
      priorConfigured: true,
    });
    trackAndPollTaskMock.mockResolvedValue({ status: "pending" });
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: activeCredential,
    });

    // When
    const outcome = await executeRegistryCredentialValidation("slow-key");

    // Then: an unjudged task must not be reported as a failed replacement
    expect(outcome).toEqual({
      status: "pending",
      credential: activeCredential,
    });
  });

  it("connects a first-time key from the authoritative read even if the watch missed settlement", async () => {
    // Given: no prior credential existed, so an active credential is ours
    trackAndPollTaskMock.mockResolvedValue({ status: "pending" });
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: activeCredential,
    });

    // When
    const outcome = await executeRegistryCredentialValidation("race-key");

    // Then
    expect(outcome).toEqual({
      status: "connected",
      credential: activeCredential,
    });
  });

  it("fails safely when the submit RPC rejects", async () => {
    // Given
    submitRegistryCredentialMock.mockRejectedValue(new Error("rpc dropped"));

    // When
    const outcome = await executeRegistryCredentialValidation("key");

    // Then
    expect(outcome).toEqual({ status: "error" });
    expect(trackAndPollTaskMock).not.toHaveBeenCalled();
  });

  it("fails safely when the authoritative re-read RPC rejects", async () => {
    // Given
    refreshRegistryCredentialMock.mockRejectedValue(new Error("rpc dropped"));

    // When
    const outcome = await executeRegistryCredentialValidation("key");

    // Then
    expect(outcome).toEqual({ status: "error" });
  });

  it("fails safely when tracking throws before the authoritative re-read", async () => {
    // Given
    trackAndPollTaskMock.mockRejectedValue(new Error("watcher crashed"));

    // When
    const outcome = await executeRegistryCredentialValidation("key");

    // Then
    expect(outcome).toEqual({ status: "error" });
    expect(refreshRegistryCredentialMock).not.toHaveBeenCalled();
  });

  it("propagates authoritative re-read failures after the watch", async () => {
    // Given
    refreshRegistryCredentialMock
      .mockResolvedValueOnce({ status: "access_denied" })
      .mockResolvedValueOnce({ status: "error" });

    // When
    const denied = await executeRegistryCredentialValidation("key");
    const failed = await executeRegistryCredentialValidation("key");

    // Then
    expect(denied).toEqual({ status: "access_denied" });
    expect(failed).toEqual({ status: "error" });
  });

  it("lets a caller opt into kind-handler notification", async () => {
    // When
    await executeRegistryCredentialValidation("key", { notifyHandler: true });

    // Then
    expect(trackAndPollTaskMock).toHaveBeenCalledWith(
      expect.objectContaining({ notifyHandler: true }),
    );
  });
});
