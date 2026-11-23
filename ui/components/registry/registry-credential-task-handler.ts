"use client";

import { completeRegistryCredentialValidation } from "@/lib/registry/credential-result";
import type { TaskKindHandler, WatchedTask } from "@/store/task-watcher/store";

const complete = async (task: WatchedTask) => {
  await completeRegistryCredentialValidation(
    task,
    task.meta.priorConfigured === "true",
  );
};

export const registryCredentialTaskHandler: TaskKindHandler = {
  onReady: complete,
  onError: complete,
};
