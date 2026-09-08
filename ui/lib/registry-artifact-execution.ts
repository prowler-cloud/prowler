import { z } from "zod";

import {
  addRegistryArtifact,
  confirmRegistryArtifactAddition,
} from "@/actions/registry/registry";
import { notifyRegistryArtifactOutcome } from "@/lib/registry-artifact-notifications";
import {
  TASK_WATCHER_STATUS,
  trackAndPollTask,
} from "@/store/task-watcher/store";
import {
  REGISTRY_ARTIFACT_ACTION,
  REGISTRY_FAILURE,
  REGISTRY_MUTATION,
  type RegistryAddArtifactInput,
  type RegistryArtifactTaskResult,
  type RegistryMutationResult,
} from "@/types/registry";

export const REGISTRY_ARTIFACT_TASK_KIND = "registry-artifact-add";

const artifactTaskResultSchema = z
  .object({ installed: z.boolean(), error: z.string().nullable() })
  .strict();

async function runRegistryArtifactAddition(
  input: RegistryAddArtifactInput,
): Promise<RegistryMutationResult> {
  let submitted;
  try {
    submitted = await addRegistryArtifact(input);
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (submitted.status !== REGISTRY_ARTIFACT_ACTION.SUBMITTED) {
    return submitted;
  }

  let tracked;
  try {
    tracked = await trackAndPollTask<RegistryArtifactTaskResult>({
      taskId: submitted.taskId,
      kind: REGISTRY_ARTIFACT_TASK_KIND,
      meta: { normalizedName: input.normalizedName },
      notifyHandler: false,
    });
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (tracked.status !== TASK_WATCHER_STATUS.READY) {
    return { status: REGISTRY_FAILURE.UNAVAILABLE };
  }

  return confirmRegistryArtifactTask(input.normalizedName, tracked.result);
}

export async function confirmRegistryArtifactTask(
  normalizedName: string,
  taskResult: unknown,
): Promise<RegistryMutationResult> {
  const result = artifactTaskResultSchema.safeParse(taskResult);
  if (
    !result.success ||
    (result.data.installed && result.data.error !== null)
  ) {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (!result.data.installed) {
    return {
      status: REGISTRY_MUTATION.REFUSED,
      message:
        result.data.error?.trim() || "The artifact could not be installed.",
    };
  }

  try {
    return await confirmRegistryArtifactAddition(normalizedName);
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
}

const installations = new Map<string, Promise<RegistryMutationResult>>();

export function executeRegistryArtifactAddition(
  input: RegistryAddArtifactInput,
): Promise<RegistryMutationResult> {
  const pending = installations.get(input.normalizedName);
  if (pending) return pending;
  const execution = runRegistryArtifactAddition(input)
    .then((result) => {
      notifyRegistryArtifactOutcome(result);
      return result;
    })
    .finally(() => installations.delete(input.normalizedName));
  installations.set(input.normalizedName, execution);
  return execution;
}
