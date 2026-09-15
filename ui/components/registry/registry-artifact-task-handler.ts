"use client";

import { confirmRegistryArtifactTask } from "@/lib/registry/artifact-execution";
import { notifyRegistryArtifactOutcome } from "@/lib/registry/artifact-notifications";
import type { TaskKindHandler } from "@/store/task-watcher/store";
import { REGISTRY_INSTALL_OPERATION } from "@/types/registry";

export const registryArtifactTaskHandler: TaskKindHandler = {
  onReady: async (task) => {
    const normalizedName = task.meta.normalizedName;
    const operation =
      task.meta.operation === REGISTRY_INSTALL_OPERATION.UPDATE
        ? REGISTRY_INSTALL_OPERATION.UPDATE
        : REGISTRY_INSTALL_OPERATION.ADD;
    const expectedVersion =
      operation === REGISTRY_INSTALL_OPERATION.UPDATE
        ? task.meta.expectedVersion?.trim()
        : undefined;
    const result =
      normalizedName &&
      (operation !== REGISTRY_INSTALL_OPERATION.UPDATE || expectedVersion)
        ? await confirmRegistryArtifactTask(
            normalizedName,
            task.result,
            expectedVersion,
          )
        : { status: "error" as const };
    notifyRegistryArtifactOutcome(result, operation);
  },
  onError: (task) =>
    notifyRegistryArtifactOutcome(
      { status: "error" },
      task.meta.operation === REGISTRY_INSTALL_OPERATION.UPDATE
        ? REGISTRY_INSTALL_OPERATION.UPDATE
        : REGISTRY_INSTALL_OPERATION.ADD,
    ),
};
