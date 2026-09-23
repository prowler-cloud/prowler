import {
  CONNECTION_TEST_STATUS,
  ConnectionTestStatus,
} from "@/types/organizations";
import {
  CONNECTION_CHECK_STATUS,
  type ConnectionCheckStatus,
} from "@/types/providers";

const DEFAULT_POLL_DELAYS_MS = [2000, 3000, 5000] as const;
export const CONNECTION_CHECK_DEFAULT_DELAYS_MS = DEFAULT_POLL_DELAYS_MS;

/**
 * `provider-connection-check` has a 120s hard time limit in Celery
 * (api/src/backend/config/celery.py `task_annotations`). With the delay ladder
 * above -- 2s, 3s, then 5s repeating -- 32 retries cover roughly 155s,
 * comfortably past the task's hard limit plus queueing/network slack.
 */
export const CONNECTION_CHECK_MAX_RETRIES = 32;

interface BuildCandidateToProviderMapParams {
  selectedCandidateIds: string[];
  providerIds: string[];
  /** Uids of the given providers, keyed by provider id. */
  resolveProviderUids: (
    providerIds: string[],
  ) => Promise<Record<string, string>>;
}

interface PollConnectionTaskOptions {
  getTaskById?: (taskId: string) => Promise<unknown>;
  sleep?: (ms: number) => Promise<void>;
  maxRetries?: number;
  delaysMs?: number[];
  signal?: AbortSignal;
}

interface PollConnectionTasksOptions
  extends Omit<PollConnectionTaskOptions, "getTaskById"> {
  /** Called once per task, the round it reaches a terminal state. */
  onSettled: (taskId: string, result: PollConnectionTaskResult) => void;
  getTasksByIds?: (taskIds: string[]) => Promise<Record<string, unknown>>;
  /**
   * Called once per task still pending after `maxRetries` is exhausted, so the
   * caller can re-read the provider's persisted connection state instead of
   * reporting a flat timeout -- the backend task may still be running past the
   * wait, or may have already finished with the UI no longer polling it.
   * Returning `null` falls back to the timeout message.
   */
  resolveExhausted?: (
    taskId: string,
  ) => Promise<PollConnectionTaskResult | null>;
}

export interface PollConnectionTaskResult {
  status: ConnectionCheckStatus;
  error?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function getPollingDelay(attempt: number, delaysMs: number[]): number {
  if (delaysMs.length === 0) {
    return DEFAULT_POLL_DELAYS_MS[DEFAULT_POLL_DELAYS_MS.length - 1];
  }
  const delayIndex = Math.min(attempt, delaysMs.length - 1);
  return delaysMs[delayIndex] ?? delaysMs[delaysMs.length - 1];
}

function sleepWithAbort(
  ms: number,
  sleep: (ms: number) => Promise<void>,
  signal?: AbortSignal,
): Promise<void> {
  if (!signal) {
    return sleep(ms);
  }

  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }

    let settled = false;
    const handleAbort = () => {
      if (settled) {
        return;
      }
      settled = true;
      resolve();
    };

    signal.addEventListener("abort", handleAbort, { once: true });
    void sleep(ms).finally(() => {
      if (!settled) {
        settled = true;
        signal.removeEventListener("abort", handleAbort);
        resolve();
      }
    });
  });
}

/**
 * Candidate id → the provider created for it. The apply response carries provider
 * ids only, so the uids identifying each candidate are read separately. A provider
 * with no resolved uid is left out rather than matched by position, which the
 * relationship order does not guarantee.
 */
export async function buildCandidateToProviderMap({
  selectedCandidateIds,
  providerIds,
  resolveProviderUids,
}: BuildCandidateToProviderMapParams): Promise<Map<string, string>> {
  const selectedCandidateIdSet = new Set(selectedCandidateIds);
  const uidByProviderId = await resolveProviderUids(providerIds);
  const mapping = new Map<string, string>();

  for (const providerId of providerIds) {
    const candidateId = uidByProviderId[providerId];
    if (!candidateId || !selectedCandidateIdSet.has(candidateId)) {
      continue;
    }
    mapping.set(candidateId, providerId);
  }

  return mapping;
}

const IN_PROGRESS_TASK_STATES = new Set([
  "available",
  "scheduled",
  "executing",
  "pending",
  "running",
]);

/**
 * The connection outcome a task payload carries, or `null` while it is still
 * running. An unreadable payload counts as terminal rather than polled forever.
 */
function readConnectionOutcome(
  taskResponse: unknown,
): PollConnectionTaskResult | null {
  if (isRecord(taskResponse) && typeof taskResponse.error === "string") {
    return {
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: taskResponse.error,
    };
  }

  const data =
    isRecord(taskResponse) && isRecord(taskResponse.data)
      ? taskResponse.data
      : null;
  const attributes = isRecord(data?.attributes) ? data.attributes : null;
  const state = typeof attributes?.state === "string" ? attributes.state : null;
  const result = isRecord(attributes?.result) ? attributes.result : null;

  if (state === "completed") {
    const connected =
      typeof result?.connected === "boolean" ? result.connected : true;
    if (connected) {
      return { status: CONNECTION_CHECK_STATUS.SUCCESS };
    }
    return {
      status: CONNECTION_CHECK_STATUS.FAILED,
      error:
        (typeof result?.error === "string" && result.error) ||
        "Connection failed for this account.",
    };
  }

  if (state === "failed") {
    return {
      status: CONNECTION_CHECK_STATUS.FAILED,
      error:
        (typeof result?.error === "string" && result.error) ||
        "Connection test task failed.",
    };
  }

  if (!state || !IN_PROGRESS_TASK_STATES.has(state)) {
    return {
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: "Unexpected task state.",
    };
  }

  return null;
}

/**
 * Polls a whole batch of connection tasks, reporting each one through `onSettled`
 * the round it settles.
 *
 * Whatever is still running is read in a single call per round: client-invoked
 * server actions run one at a time through Next's action queue, so polling task
 * by task would cost a round trip per task per round and stall every other action
 * behind it.
 */
export async function pollConnectionTasks(
  taskIds: string[],
  {
    onSettled,
    getTasksByIds,
    sleep = async (ms: number) =>
      new Promise((resolve) => setTimeout(resolve, ms)),
    maxRetries = CONNECTION_CHECK_MAX_RETRIES,
    delaysMs = [...DEFAULT_POLL_DELAYS_MS],
    signal,
    resolveExhausted,
  }: PollConnectionTasksOptions,
): Promise<void> {
  const pending = new Set(taskIds.filter(Boolean));
  if (pending.size === 0) {
    return;
  }

  const tasksFetcher =
    getTasksByIds ??
    (async (currentTaskIds: string[]) => {
      const { getTasksByIds: readTasks } = await import("@/actions/task/tasks");
      return readTasks(currentTaskIds);
    });

  const settleRemaining = (error: string) => {
    for (const taskId of Array.from(pending)) {
      onSettled(taskId, { status: CONNECTION_CHECK_STATUS.FAILED, error });
    }
    pending.clear();
  };

  for (let attempt = 0; attempt < maxRetries; attempt += 1) {
    if (signal?.aborted) {
      settleRemaining("Connection test cancelled.");
      return;
    }

    const snapshots = await tasksFetcher(Array.from(pending));
    if (signal?.aborted) {
      settleRemaining("Connection test cancelled.");
      return;
    }

    for (const taskId of Array.from(pending)) {
      // A task missing from the batch read gets another round rather than being
      // reported as a failure the API never stated.
      if (!(taskId in snapshots)) {
        continue;
      }

      const outcome = readConnectionOutcome(snapshots[taskId]);
      if (!outcome) {
        continue;
      }

      pending.delete(taskId);
      onSettled(taskId, outcome);
    }

    if (pending.size === 0) {
      return;
    }

    await sleepWithAbort(getPollingDelay(attempt, delaysMs), sleep, signal);
  }

  if (resolveExhausted) {
    // Sequential, not `Promise.all`: each call goes through its own
    // `getProvider` server action, and client-invoked server actions run one
    // at a time through Next's action queue (see `pollConnectionTasks`'s own
    // batched read above) -- running them "concurrently" from here would not
    // shorten the wait, only reorder it.
    for (const taskId of Array.from(pending)) {
      if (signal?.aborted) {
        settleRemaining("Connection test cancelled.");
        return;
      }

      const resolved = await resolveExhausted(taskId);

      // The signal can abort while `resolveExhausted` itself is in flight; its
      // result must not be accepted after that, or a check the caller has
      // already moved on from could still report success.
      if (signal?.aborted) {
        settleRemaining("Connection test cancelled.");
        return;
      }

      if (resolved) {
        pending.delete(taskId);
        onSettled(taskId, resolved);
      }
    }
  }

  settleRemaining("Connection test timed out.");
}

/**
 * Polls a generic async task until it settles. Unlike {@link pollConnectionTasks}
 * it does not interpret a connection result; it is used for organization/node
 * deletion, which the API answers with a `202` + task. Its result is typed with
 * `ConnectionCheckStatus` only because that is the connection-specific alias of
 * the generic `TASK_OUTCOME` (`types/tasks.ts`) already in scope here -- the
 * three outcomes (succeeded / failed / still running) apply to any polled task,
 * not just a connection check.
 */
export async function pollTaskCompletion(
  taskId: string,
  {
    getTaskById,
    sleep = async (ms: number) =>
      new Promise((resolve) => setTimeout(resolve, ms)),
    maxRetries = 20,
    delaysMs = [...DEFAULT_POLL_DELAYS_MS],
    signal,
  }: PollConnectionTaskOptions = {},
): Promise<PollConnectionTaskResult> {
  const taskFetcher =
    getTaskById ??
    (async (currentTaskId: string) => {
      const { getTask } = await import("@/actions/task/tasks");
      return getTask(currentTaskId);
    });

  for (let attempt = 0; attempt < maxRetries; attempt += 1) {
    if (signal?.aborted) {
      return {
        status: CONNECTION_CHECK_STATUS.FAILED,
        error: "Deletion cancelled.",
      };
    }

    const taskResponse = await taskFetcher(taskId);
    if (signal?.aborted) {
      return {
        status: CONNECTION_CHECK_STATUS.FAILED,
        error: "Deletion cancelled.",
      };
    }

    if (isRecord(taskResponse) && typeof taskResponse.error === "string") {
      return {
        status: CONNECTION_CHECK_STATUS.FAILED,
        error: taskResponse.error,
      };
    }

    const data =
      isRecord(taskResponse) && isRecord(taskResponse.data)
        ? taskResponse.data
        : null;
    const attributes = isRecord(data?.attributes) ? data.attributes : null;
    const state =
      typeof attributes?.state === "string" ? attributes.state : null;
    const result = isRecord(attributes?.result) ? attributes.result : null;

    if (state === "completed") {
      return { status: CONNECTION_CHECK_STATUS.SUCCESS };
    }

    if (state === "failed") {
      return {
        status: CONNECTION_CHECK_STATUS.FAILED,
        error:
          (typeof result?.error === "string" && result.error) ||
          "The deletion task failed.",
      };
    }

    // A cancelled task is a real terminal state, not an unreadable one.
    if (state === "cancelled") {
      return {
        status: CONNECTION_CHECK_STATUS.FAILED,
        error: "The deletion was cancelled.",
      };
    }

    if (!state || !IN_PROGRESS_TASK_STATES.has(state)) {
      return {
        status: CONNECTION_CHECK_STATUS.FAILED,
        error: "Unexpected task state.",
      };
    }

    await sleepWithAbort(getPollingDelay(attempt, delaysMs), sleep, signal);
  }

  return {
    status: CONNECTION_CHECK_STATUS.FAILED,
    error: "Deletion timed out.",
  };
}

export function getLaunchableProviderIds(
  providerIds: string[],
  connectionResults: Record<string, ConnectionTestStatus>,
): string[] {
  return providerIds.filter(
    (providerId) =>
      connectionResults[providerId] === CONNECTION_TEST_STATUS.SUCCESS,
  );
}

export function canAdvanceToLaunchStep(
  providerIds: string[],
  connectionResults: Record<string, ConnectionTestStatus>,
): boolean {
  return getLaunchableProviderIds(providerIds, connectionResults).length > 0;
}
