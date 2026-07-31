import {
  CONNECTION_TEST_STATUS,
  ConnectionTestStatus,
} from "@/types/organizations";

const DEFAULT_POLL_DELAYS_MS = [2000, 3000, 5000] as const;

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
}

export interface PollConnectionTaskResult {
  success: boolean;
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
    return { success: false, error: taskResponse.error };
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
      return { success: true };
    }
    return {
      success: false,
      error:
        (typeof result?.error === "string" && result.error) ||
        "Connection failed for this account.",
    };
  }

  if (state === "failed") {
    return {
      success: false,
      error:
        (typeof result?.error === "string" && result.error) ||
        "Connection test task failed.",
    };
  }

  if (!state || !IN_PROGRESS_TASK_STATES.has(state)) {
    return { success: false, error: "Unexpected task state." };
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
    maxRetries = 20,
    delaysMs = [...DEFAULT_POLL_DELAYS_MS],
    signal,
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
      onSettled(taskId, { success: false, error });
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

  settleRemaining("Connection test timed out.");
}

/**
 * Polls a generic async task until it settles. Unlike {@link pollConnectionTasks}
 * it does not interpret a connection result; it is used for organization/node
 * deletion, which the API answers with a `202` + task.
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
      return { success: false, error: "Deletion cancelled." };
    }

    const taskResponse = await taskFetcher(taskId);
    if (signal?.aborted) {
      return { success: false, error: "Deletion cancelled." };
    }

    if (isRecord(taskResponse) && typeof taskResponse.error === "string") {
      return { success: false, error: taskResponse.error };
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
      return { success: true };
    }

    if (state === "failed") {
      return {
        success: false,
        error:
          (typeof result?.error === "string" && result.error) ||
          "The deletion task failed.",
      };
    }

    // A cancelled task is a real terminal state, not an unreadable one.
    if (state === "cancelled") {
      return { success: false, error: "The deletion was cancelled." };
    }

    if (!state || !IN_PROGRESS_TASK_STATES.has(state)) {
      return { success: false, error: "Unexpected task state." };
    }

    await sleepWithAbort(getPollingDelay(attempt, delaysMs), sleep, signal);
  }

  return { success: false, error: "Deletion timed out." };
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
