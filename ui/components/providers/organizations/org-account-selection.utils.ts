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

export async function runWithConcurrencyLimit<T, R>(
  items: T[],
  concurrencyLimit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }

  const normalizedConcurrency = Math.max(1, Math.floor(concurrencyLimit));
  const results = new Array<R>(items.length);
  let currentIndex = 0;

  const runWorker = async () => {
    while (currentIndex < items.length) {
      const assignedIndex = currentIndex;
      currentIndex += 1;
      results[assignedIndex] = await worker(
        items[assignedIndex],
        assignedIndex,
      );
    }
  };

  const workers = Array.from(
    { length: Math.min(normalizedConcurrency, items.length) },
    () => runWorker(),
  );

  await Promise.all(workers);
  return results;
}

/**
 * Candidate id → the provider created for it.
 *
 * The apply response carries provider *ids* only — it cannot be asked to include
 * the providers themselves — so the uids that identify each candidate are read
 * separately. Providers whose uid was not resolved, or that belong to a candidate
 * outside this selection, are left out rather than guessed at by position: the
 * relationship order is not the selection order.
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

export async function pollConnectionTask(
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
  const inProgressStates = new Set([
    "available",
    "scheduled",
    "executing",
    "pending",
    "running",
  ]);
  const taskFetcher =
    getTaskById ??
    (async (currentTaskId: string) => {
      const { getTask } = await import("@/actions/task/tasks");
      return getTask(currentTaskId);
    });

  for (let attempt = 0; attempt < maxRetries; attempt += 1) {
    if (signal?.aborted) {
      return { success: false, error: "Connection test cancelled." };
    }

    const taskResponse = await taskFetcher(taskId);
    if (signal?.aborted) {
      return { success: false, error: "Connection test cancelled." };
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

    if (!state || !inProgressStates.has(state)) {
      return { success: false, error: "Unexpected task state." };
    }

    await sleepWithAbort(getPollingDelay(attempt, delaysMs), sleep, signal);
  }

  return { success: false, error: "Connection test timed out." };
}

/**
 * Polls a generic async task until it settles, reporting success only when the
 * task completes. Unlike {@link pollConnectionTask} it does not interpret a
 * connection result — it is used for organization/node deletion, which the API
 * returns as a `202` + task. Injectable for tests (getTaskById/sleep/signal).
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
  const inProgressStates = new Set([
    "available",
    "scheduled",
    "executing",
    "pending",
    "running",
  ]);
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

    // A revoked task is a real terminal state, not something unreadable.
    if (state === "cancelled") {
      return { success: false, error: "The deletion was cancelled." };
    }

    if (!state || !inProgressStates.has(state)) {
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
