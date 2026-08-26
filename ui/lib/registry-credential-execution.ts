import {
  refreshRegistryCredential,
  submitRegistryCredential,
} from "@/actions/registry/registry";
import {
  isActiveRegistryCredential,
  REGISTRY_CREDENTIAL_TASK_KIND,
} from "@/lib/registry-credential-task";
import {
  TASK_WATCHER_STATUS,
  type TaskTrackingResult,
  trackAndPollTask,
} from "@/store/task-watcher/store";
import {
  REGISTRY_CREDENTIAL_ACTION,
  REGISTRY_CREDENTIAL_READ,
  REGISTRY_FAILURE,
  type RegistryCredentialReadResult,
  type RegistryCredentialStatus,
  type RegistryCredentialSubmitResult,
} from "@/types/registry";

/**
 * Upper bound this flow waits on the task watcher before falling back to the
 * authoritative credential re-read. The watcher itself keeps polling for up
 * to 15 × ~20s rounds, which is far too long to hold a modal in Connecting…
 * when no worker consumes the queue; one ~20s server round plus margin is
 * enough to catch every promptly-settled validation.
 */
export const REGISTRY_CREDENTIAL_WATCH_TIMEOUT_MS = 30_000;

const watchDeadline = (ms: number) => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const promise = new Promise<TaskTrackingResult>((resolve) => {
    timer = setTimeout(
      () => resolve({ status: TASK_WATCHER_STATUS.PENDING }),
      ms,
    );
  });
  return { promise, cancel: () => clearTimeout(timer) };
};

export type RegistryCredentialValidationOutcome =
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.CONNECTED;
      credential: RegistryCredentialStatus;
    }
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.PENDING;
      credential: RegistryCredentialStatus;
    }
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.INVALID;
      credential: RegistryCredentialStatus;
    }
  | { status: typeof REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED }
  | { status: typeof REGISTRY_FAILURE.ACCESS_DENIED }
  | { status: typeof REGISTRY_FAILURE.ERROR };

/**
 * Submits a Registry API key, watches its validation task through the house
 * task watcher, then classifies the settled outcome from the authoritative
 * credential re-read. Mirrors `executeJiraDispatchBatches`: the awaiting
 * caller owns UI feedback by default (`notifyHandler: false`), while resumed
 * tasks notify `registryCredentialTaskHandler`.
 */
export async function executeRegistryCredentialValidation(
  key: string,
  options: { notifyHandler?: boolean } = {},
): Promise<RegistryCredentialValidationOutcome> {
  // Every server-action RPC below can reject outright (network drop, server
  // restart); this flow must always resolve to a typed outcome so the dialog
  // is never stranded in Connecting….
  let submitted: RegistryCredentialSubmitResult;
  try {
    submitted = await submitRegistryCredential(key);
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (submitted.status === REGISTRY_FAILURE.ACCESS_DENIED) {
    return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  }
  if (submitted.status === REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED) {
    return { status: REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED };
  }
  if (submitted.status !== REGISTRY_CREDENTIAL_ACTION.SUBMITTED) {
    return { status: REGISTRY_FAILURE.ERROR };
  }

  // A task nobody consumes never settles; the deadline resolves the race as
  // still PENDING so the authoritative re-read below decides the outcome.
  // The watcher keeps polling in the background either way.
  let tracked: TaskTrackingResult;
  const deadline = watchDeadline(REGISTRY_CREDENTIAL_WATCH_TIMEOUT_MS);
  try {
    tracked = await Promise.race([
      trackAndPollTask({
        taskId: submitted.taskId,
        kind: REGISTRY_CREDENTIAL_TASK_KIND,
        meta: {},
        notifyHandler: options.notifyHandler ?? false,
      }),
      deadline.promise,
    ]);
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  } finally {
    deadline.cancel();
  }

  let read: RegistryCredentialReadResult;
  try {
    read = await refreshRegistryCredential();
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (read.status === REGISTRY_FAILURE.ACCESS_DENIED) {
    return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  }
  if (read.status !== REGISTRY_CREDENTIAL_READ.STATUS) {
    return { status: REGISTRY_FAILURE.ERROR };
  }

  const { credential } = read;
  // With no prior credential an active status can only belong to the key we
  // just submitted, so the authoritative read outranks a missed settlement.
  if (
    isActiveRegistryCredential(credential) &&
    (tracked.status === TASK_WATCHER_STATUS.READY || !submitted.priorConfigured)
  ) {
    return { status: REGISTRY_CREDENTIAL_ACTION.CONNECTED, credential };
  }
  if (credential.validationPending) {
    return { status: REGISTRY_CREDENTIAL_ACTION.PENDING, credential };
  }
  // An unsettled watch has not judged the key; report it still pending
  // rather than invalid or a failed replacement.
  if (tracked.status === TASK_WATCHER_STATUS.PENDING) {
    return { status: REGISTRY_CREDENTIAL_ACTION.PENDING, credential };
  }
  if (submitted.priorConfigured) {
    return { status: REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED };
  }
  return { status: REGISTRY_CREDENTIAL_ACTION.INVALID, credential };
}
