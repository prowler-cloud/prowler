import { beforeEach, describe, expect, it, vi } from "vitest";

import type { WatchedTask } from "@/store/task-watcher/store";

const { confirmRegistryArtifactAddition, toast } = vi.hoisted(() => ({
  confirmRegistryArtifactAddition: vi.fn(),
  toast: vi.fn(),
}));
vi.mock("@/actions/registry/registry", () => ({
  addRegistryArtifact: vi.fn(),
  confirmRegistryArtifactAddition,
}));
vi.mock("@/components/shadcn/toast", () => ({ toast }));
vi.mock("@/store/task-watcher/store", () => ({
  trackAndPollTask: vi.fn(),
  TASK_WATCHER_STATUS: { READY: "ready" },
}));

import { registryArtifactTaskHandler } from "./registry-artifact-task-handler";

const task: WatchedTask = {
  taskId: "installation-task",
  kind: "registry-artifact-add",
  status: "ready",
  startedAt: Date.now(),
  meta: { normalizedName: "acme-provider" },
  result: { installed: true, error: null },
};

describe("resumed Registry installations", () => {
  beforeEach(() => vi.clearAllMocks());

  it("waits for membership confirmation before one success notification and selector refresh", async () => {
    let confirm!: (value: unknown) => void;
    confirmRegistryArtifactAddition.mockReturnValue(
      new Promise((resolve) => {
        confirm = resolve;
      }),
    );
    const listener = vi.fn();
    window.addEventListener("registry-artifacts-changed", listener);
    const completion = registryArtifactTaskHandler.onReady(task);
    expect(confirmRegistryArtifactAddition).toHaveBeenCalledWith(
      "acme-provider",
    );
    expect(toast).not.toHaveBeenCalled();
    expect(listener).not.toHaveBeenCalled();
    const tenantArtifacts = {
      artifacts: [{ normalizedName: "acme-provider" }],
    };
    confirm({ status: "confirmed", tenantArtifacts });
    await completion;
    expect(toast).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Artifact added" }),
    );
    expect(listener).toHaveBeenCalledOnce();
    expect(listener.mock.calls[0][0].detail).toEqual(tenantArtifacts);
    window.removeEventListener("registry-artifacts-changed", listener);
  });

  it.each([
    { installed: false, error: "Installation rejected" },
    { installed: true, error: "Partial failure" },
    undefined,
  ])(
    "never announces success for unsuccessful task results",
    async (result) => {
      await registryArtifactTaskHandler.onReady({ ...task, result });
      expect(confirmRegistryArtifactAddition).not.toHaveBeenCalled();
      expect(toast).toHaveBeenCalledOnce();
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      );
    },
  );

  it("reports a failed confirmation read without announcing availability", async () => {
    confirmRegistryArtifactAddition.mockRejectedValue(new Error("Unavailable"));
    await registryArtifactTaskHandler.onReady(task);
    expect(toast).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive" }),
    );
  });
});
