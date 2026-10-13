import { z } from "zod";

import {
  addRegistryArtifact,
  confirmRegistryArtifactAddition,
} from "@/actions/registry/registry";
import { notifyRegistryArtifactOutcome } from "@/lib/registry/artifact-notifications";
import {
  TASK_WATCHER_STATUS,
  trackAndPollTask,
} from "@/store/task-watcher/store";
import {
  REGISTRY_ARTIFACT_ACTION,
  REGISTRY_FAILURE,
  REGISTRY_INSTALL_OPERATION,
  REGISTRY_MUTATION,
  type RegistryArtifactExecutionInput,
  type RegistryArtifactTaskResult,
  type RegistryMutationResult,
} from "@/types/registry";

export const REGISTRY_ARTIFACT_TASK_KIND = "registry-artifact-add";

const artifactTaskResultSchema = z
  .object({ installed: z.boolean(), error: z.string().nullable() })
  .strict();

async function runRegistryArtifactAddition(
  input: RegistryArtifactExecutionInput,
): Promise<RegistryMutationResult> {
  const expectedVersion =
    input.operation === REGISTRY_INSTALL_OPERATION.UPDATE
      ? input.versionSpec.trim()
      : undefined;
  if (expectedVersion === "") return { status: REGISTRY_FAILURE.ERROR };
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
      meta: {
        normalizedName: input.normalizedName,
        ...(expectedVersion
          ? { operation: REGISTRY_INSTALL_OPERATION.UPDATE, expectedVersion }
          : {}),
      },
      notifyHandler: false,
    });
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (tracked.status !== TASK_WATCHER_STATUS.READY) {
    return { status: REGISTRY_FAILURE.UNAVAILABLE };
  }

  return confirmRegistryArtifactTask(
    input.normalizedName,
    tracked.result,
    expectedVersion,
  );
}

export async function confirmRegistryArtifactTask(
  normalizedName: string,
  taskResult: unknown,
  expectedVersion?: string,
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
      // Task errors are backend diagnostics, not user-facing refusal codes.
      message: "The artifact could not be installed.",
    };
  }

  try {
    return await (expectedVersion === undefined
      ? confirmRegistryArtifactAddition(normalizedName)
      : confirmRegistryArtifactAddition(normalizedName, expectedVersion));
  } catch {
    return {
      status:
        expectedVersion === undefined
          ? REGISTRY_FAILURE.ERROR
          : REGISTRY_MUTATION.REFRESH_FAILED,
    };
  }
}

const installations = new Map<string, Promise<RegistryMutationResult>>();

export function executeRegistryArtifactAddition(
  input: RegistryArtifactExecutionInput,
): Promise<RegistryMutationResult> {
  const pending = installations.get(input.normalizedName);
  if (pending) return pending;
  const execution = runRegistryArtifactAddition(input)
    .then((result) => {
      notifyRegistryArtifactOutcome(result, input.operation);
      return result;
    })
    .finally(() => installations.delete(input.normalizedName));
  installations.set(input.normalizedName, execution);
  return execution;
}
