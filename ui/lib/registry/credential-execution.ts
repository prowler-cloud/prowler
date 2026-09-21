import { submitRegistryCredential } from "@/actions/registry/registry";
import {
  completeRegistryCredentialValidation,
  type RegistryCredentialValidationOutcome,
} from "@/lib/registry/credential-result";
import { REGISTRY_CREDENTIAL_TASK_KIND } from "@/lib/registry/credential-task";
import {
  TASK_WATCHER_STATUS,
  trackAndPollTask,
} from "@/store/task-watcher/store";
import { REGISTRY_CREDENTIAL_ACTION, REGISTRY_FAILURE } from "@/types/registry";

export const REGISTRY_CREDENTIAL_WATCH_TIMEOUT_MS = 30_000;

/** The live operation owns confirmation. Reloads resume through the kind handler. */
export async function executeRegistryCredentialValidation(
  key: string,
  options: { notifyHandler?: boolean } = {},
): Promise<RegistryCredentialValidationOutcome> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const submitted = await submitRegistryCredential(key);
    if (
      submitted.status === REGISTRY_FAILURE.ACCESS_DENIED ||
      submitted.status === REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED
    )
      return { status: submitted.status };
    if (submitted.status !== REGISTRY_CREDENTIAL_ACTION.SUBMITTED)
      return { status: REGISTRY_FAILURE.ERROR };

    // Only non-secret operation context survives reload. Suppression is in-memory
    // and disappears on reload, when the registered handler takes ownership.
    const completion = trackAndPollTask({
      taskId: submitted.taskId,
      kind: REGISTRY_CREDENTIAL_TASK_KIND,
      meta: { priorConfigured: String(submitted.priorConfigured) },
      notifyHandler: false,
    }).then((tracked) =>
      tracked.status === TASK_WATCHER_STATUS.PENDING
        ? ({ status: REGISTRY_CREDENTIAL_ACTION.PENDING } as const)
        : completeRegistryCredentialValidation(
            tracked,
            submitted.priorConfigured,
            options.notifyHandler ?? true,
          ),
    );
    // Let the dialog recover while completion continues across navigation.
    // A deadline is not a verdict: only task settlement can confirm the key.
    const deadline = new Promise<RegistryCredentialValidationOutcome>(
      (resolve) => {
        timer = setTimeout(
          () => resolve({ status: REGISTRY_CREDENTIAL_ACTION.PENDING }),
          REGISTRY_CREDENTIAL_WATCH_TIMEOUT_MS,
        );
      },
    );
    return await Promise.race([completion, deadline]);
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  } finally {
    clearTimeout(timer);
  }
}
