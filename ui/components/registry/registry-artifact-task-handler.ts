"use client";

import { confirmRegistryArtifactTask } from "@/lib/registry/artifact-execution";
import { notifyRegistryArtifactOutcome } from "@/lib/registry/artifact-notifications";
import type { TaskKindHandler } from "@/store/task-watcher/store";

export const registryArtifactTaskHandler: TaskKindHandler = {
  onReady: async (task) => {
    const normalizedName = task.meta.normalizedName;
    const result = normalizedName
      ? await confirmRegistryArtifactTask(normalizedName, task.result)
      : { status: "error" as const };
    notifyRegistryArtifactOutcome(result);
  },
  onError: () => notifyRegistryArtifactOutcome({ status: "error" }),
};
