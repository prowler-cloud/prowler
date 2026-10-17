import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Toast, ToastProvider, ToastViewport } from "@/components/shadcn/toast";
import type { WatchedTask } from "@/store/task-watcher/store";

const { confirmRegistryArtifactAddition, toast } = vi.hoisted(() => ({
  confirmRegistryArtifactAddition: vi.fn(),
  toast: vi.fn(),
}));
vi.mock("@/actions/registry/registry", () => ({
  addRegistryArtifact: vi.fn(),
  confirmRegistryArtifactAddition,
}));
vi.mock("@/components/shadcn/toast", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/shadcn/toast")>()),
  toast,
}));
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

  it("resumes an update with its expected version and announces one update", async () => {
    // Given
    confirmRegistryArtifactAddition.mockResolvedValue({
      status: "confirmed",
      tenantArtifacts: [],
    });
    // When
    await registryArtifactTaskHandler.onReady({
      ...task,
      meta: { ...task.meta, operation: "update", expectedVersion: "2.0.0" },
    });
    // Then
    expect(confirmRegistryArtifactAddition).toHaveBeenCalledWith(
      "acme-provider",
      "2.0.0",
    );
    expect(toast).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Artifact updated" }),
    );
  });

  it.each(["refresh_failed", "error"])(
    "announces an update failure for %s after reload",
    async (status) => {
      // Given
      confirmRegistryArtifactAddition.mockResolvedValue({ status });
      // When
      await registryArtifactTaskHandler.onReady({
        ...task,
        meta: {
          ...task.meta,
          operation: "update",
          expectedVersion: "2.0.0",
        },
      });
      // Then
      expect(toast).toHaveBeenCalledOnce();
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Artifact could not be updated",
          variant: "destructive",
          ...(status === "refresh_failed"
            ? {
                description:
                  "Update could not be confirmed. Refresh Registry before retrying.",
              }
            : {}),
        }),
      );
    },
  );

  it("never confirms an update with missing persisted target metadata", async () => {
    // Given / When
    await registryArtifactTaskHandler.onReady({
      ...task,
      meta: { ...task.meta, operation: "update" },
    });
    // Then
    expect(confirmRegistryArtifactAddition).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Artifact could not be updated" }),
    );
  });

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
    expect(toast.mock.calls[0][0]).not.toHaveProperty("description");
    render(
      <ToastProvider>
        <Toast open>{toast.mock.calls[0][0].action}</Toast>
        <ToastViewport />
      </ToastProvider>,
    );
    expect(
      screen.getByRole("link", { name: "Go to Providers" }),
    ).toHaveAttribute("href", "/providers");
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

  it("keeps backend diagnostics out of notifications after reload", async () => {
    // Given
    const result = {
      installed: false,
      error: "Private diagnostic: /srv/registry/customer",
    };

    // When
    await registryArtifactTaskHandler.onReady({ ...task, result });

    // Then
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({
        variant: "destructive",
        description: "The artifact could not be installed.",
      }),
    );
    expect(confirmRegistryArtifactAddition).not.toHaveBeenCalled();
  });

  it("reports a failed confirmation read without announcing availability", async () => {
    confirmRegistryArtifactAddition.mockRejectedValue(new Error("Unavailable"));
    await registryArtifactTaskHandler.onReady(task);
    expect(toast).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive" }),
    );
  });
});
