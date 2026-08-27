import { z } from "zod";

import {
  addRegistryArtifact,
  confirmRegistryArtifactAddition,
} from "@/actions/registry/registry";
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

export async function executeRegistryArtifactAddition(
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
      meta: {},
      notifyHandler: false,
    });
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (tracked.status !== TASK_WATCHER_STATUS.READY) {
    return { status: REGISTRY_FAILURE.UNAVAILABLE };
  }

  const result = artifactTaskResultSchema.safeParse(tracked.result);
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
    return await confirmRegistryArtifactAddition(input.normalizedName);
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
}
