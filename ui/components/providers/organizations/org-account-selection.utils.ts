import {
  CONNECTION_TEST_STATUS,
  ConnectionTestStatus,
} from "@/types/organizations";

const DEFAULT_CONCURRENCY_LIMIT = 5;
const DEFAULT_POLL_DELAYS_MS = [2000, 3000, 5000] as const;

interface AccountProviderMapping {
  account_id: string;
  provider_id: string;
}

interface BuildAccountToProviderMapParams {
  selectedAccountIds: string[];
  providerIds: string[];
  applyResult: unknown;
  resolveProviderUidById: (providerId: string) => Promise<string | null>;
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

function normalizeAccountProviderMapping(
  value: unknown,
): AccountProviderMapping | null {
  if (!isRecord(value)) {
    return null;
  }

  const attributes = isRecord(value.attributes) ? value.attributes : null;
  const accountId =
    (typeof value.account_id === "string" && value.account_id) ||
    (typeof attributes?.account_id === "string" && attributes.account_id) ||
    (typeof value.id === "string" && value.id) ||
    null;

  const providerId =
    (typeof value.provider_id === "string" && value.provider_id) ||
    (typeof attributes?.provider_id === "string" && attributes.provider_id) ||
    null;

  if (!accountId || !providerId) {
    return null;
  }

  return {
    account_id: accountId,
    provider_id: providerId,
  };
}

function extractAccountProviderMappings(applyResult: unknown) {
  if (!isRecord(applyResult)) {
    return [];
  }

  const data = isRecord(applyResult.data) ? applyResult.data : null;
  if (!data) {
    return [];
  }

  const attributes = isRecord(data.attributes) ? data.attributes : null;
  const relationships = isRecord(data.relationships)
    ? data.relationships
    : null;

  const attributeMappings = Array.isArray(attributes?.account_provider_mappings)
    ? attributes.account_provider_mappings
    : [];
  const relationshipNode = isRecord(relationships?.account_provider_mappings)
    ? relationships.account_provider_mappings
    : null;
  const relationshipMappings = Array.isArray(relationshipNode?.data)
    ? relationshipNode.data
    : [];

  return [...attributeMappings, ...relationshipMappings]
    .map(normalizeAccountProviderMapping)
    .filter((mapping): mapping is AccountProviderMapping => mapping !== null);
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

export async function buildAccountToProviderMap({
  selectedAccountIds,
  providerIds,
  applyResult,
  resolveProviderUidById,
}: BuildAccountToProviderMapParams): Promise<Map<string, string>> {
  const selectedAccountIdSet = new Set(selectedAccountIds);

  const explicitMappings = extractAccountProviderMappings(applyResult);
  if (explicitMappings.length > 0) {
    const mappedProviders = new Map<string, string>();

    for (const mapping of explicitMappings) {
      if (!selectedAccountIdSet.has(mapping.account_id)) {
        continue;
      }
      mappedProviders.set(mapping.account_id, mapping.provider_id);
    }

    if (mappedProviders.size > 0) {
      return mappedProviders;
    }
  }

  const fallbackEntries = await runWithConcurrencyLimit(
    providerIds,
    DEFAULT_CONCURRENCY_LIMIT,
    async (providerId) => {
      const providerUid = await resolveProviderUidById(providerId);
      if (!providerUid || !selectedAccountIdSet.has(providerUid)) {
        return null;
      }
      return { accountId: providerUid, providerId };
    },
  );

  const fallbackMapping = new Map<string, string>();
  for (const entry of fallbackEntries) {
    if (!entry) {
      continue;
    }
    fallbackMapping.set(entry.accountId, entry.providerId);
  }

  return fallbackMapping;
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
