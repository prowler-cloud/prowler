import { beforeEach, describe, expect, it, vi } from "vitest";

import { executeRegistryArtifactAddition } from "./registry-artifact-execution";

// prettier-ignore
const { addRegistryArtifactMock, confirmRegistryArtifactAdditionMock, trackAndPollTaskMock } = vi.hoisted(() => ({ addRegistryArtifactMock: vi.fn(), confirmRegistryArtifactAdditionMock: vi.fn(), trackAndPollTaskMock: vi.fn() }));

// prettier-ignore
vi.mock("@/actions/registry/registry", () => ({ addRegistryArtifact: addRegistryArtifactMock, confirmRegistryArtifactAddition: confirmRegistryArtifactAdditionMock }));

// prettier-ignore
vi.mock("@/store/task-watcher/store", () => ({ TASK_WATCHER_STATUS: { READY: "ready", ERROR: "error" }, trackAndPollTask: trackAndPollTaskMock }));

const artifactInput = { normalizedName: "prowler-aws", versionSpec: "2.0.0" };

describe("executeRegistryArtifactAddition", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    addRegistryArtifactMock.mockResolvedValue({
      status: "submitted",
      taskId: "artifact-task",
    });
    trackAndPollTaskMock.mockResolvedValue({
      status: "ready",
      result: { installed: true, error: null },
    });
    confirmRegistryArtifactAdditionMock.mockResolvedValue({
      status: "confirmed",
      tenantArtifacts: [],
    });
  });

  // prettier-ignore
  it.each([["This version cannot be installed.", "This version cannot be installed."], [null, "The artifact could not be installed."], ["", "The artifact could not be installed."], ["   ", "The artifact could not be installed."]])("returns a safe task refusal for error %j without confirmation", async (error, message) => {
    // Given
    trackAndPollTaskMock.mockResolvedValue({ status: "ready", result: { installed: false, error } });
    // When
    const outcome = await executeRegistryArtifactAddition(artifactInput);
    // Then
    expect(outcome).toEqual({ status: "refused", message });
    expect(confirmRegistryArtifactAdditionMock).not.toHaveBeenCalled();
  });

  // prettier-ignore
  it.each([["an otherwise valid result with an extra field", { installed: true, error: null, reason: "private deployment detail" }], ["an installed result with an error", { installed: true, error: "unexpected failure" }]])("returns error for %s without confirmation", async (_case, result) => {
    // Given
    trackAndPollTaskMock.mockResolvedValue({ status: "ready", result });
    // When
    const outcome = await executeRegistryArtifactAddition(artifactInput);
    // Then
    expect(outcome).toEqual({ status: "error" });
    expect(confirmRegistryArtifactAdditionMock).not.toHaveBeenCalled();
  });

  it("maps failed tasks to unavailable without confirmation", async () => {
    // Given
    trackAndPollTaskMock.mockResolvedValue({
      status: "error",
      error: "failed",
    });
    // When
    const outcome = await executeRegistryArtifactAddition(artifactInput);
    // Then
    expect(outcome).toEqual({ status: "unavailable" });
    expect(confirmRegistryArtifactAdditionMock).not.toHaveBeenCalled();
  });

  it("uses the error catch when polling throws", async () => {
    // Given
    trackAndPollTaskMock.mockRejectedValue(new Error("watcher crashed"));
    // When
    const outcome = await executeRegistryArtifactAddition(artifactInput);
    // Then
    expect(outcome).toEqual({ status: "error" });
    expect(confirmRegistryArtifactAdditionMock).not.toHaveBeenCalled();
  });

  it("does not poll a synchronous 409 onboarding outcome", async () => {
    // Given
    addRegistryArtifactMock.mockResolvedValue({ status: "onboarding" });
    // When
    const outcome = await executeRegistryArtifactAddition(artifactInput);
    // Then
    expect(outcome).toEqual({ status: "onboarding" });
    expect(confirmRegistryArtifactAdditionMock).not.toHaveBeenCalled();
    expect(trackAndPollTaskMock).not.toHaveBeenCalled();
  });

  it("confirms presence after a completed installed task", async () => {
    // Given
    // When
    const outcome = await executeRegistryArtifactAddition(artifactInput);
    // Then
    expect(outcome).toEqual({ status: "confirmed", tenantArtifacts: [] });
    expect(trackAndPollTaskMock).toHaveBeenCalledWith({
      taskId: "artifact-task",
      kind: "registry-artifact-add",
      meta: {},
      notifyHandler: false,
    });
    expect(confirmRegistryArtifactAdditionMock).toHaveBeenCalledOnce();
    expect(confirmRegistryArtifactAdditionMock).toHaveBeenCalledWith(
      "prowler-aws",
    );
  });
});
