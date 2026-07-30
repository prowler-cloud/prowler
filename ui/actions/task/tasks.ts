"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { runWithConcurrencyLimit } from "@/lib/concurrency";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

export const getTask = async (taskId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/tasks/${taskId}`);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/** Task reads in flight at once inside one round of polling. */
const TASK_READ_CONCURRENCY_LIMIT = 10;

/**
 * Reads several tasks in one call, keyed by task id, each entry shaped exactly
 * like {@link getTask}'s so callers parse one payload shape either way.
 *
 * A caller polling N tasks cannot loop over `getTask`: client-invoked server
 * actions run one at a time through Next's global action queue, so N tasks per
 * round means N sequential round trips, and the polls compete with whatever
 * else the flow is doing. This collapses a round into a single action.
 *
 * The reads are still one request per task — `TaskFilter` exposes no id filter,
 * so the collection cannot be asked for a specific set — but they overlap here
 * instead of queueing on the client.
 */
export const getTasksByIds = async (
  taskIds: string[],
): Promise<Record<string, unknown>> => {
  const uniqueIds = Array.from(new Set(taskIds.filter(Boolean)));
  if (uniqueIds.length === 0) {
    return {};
  }

  const headers = await getAuthHeaders({ contentType: false });
  const snapshots: Record<string, unknown> = {};

  await runWithConcurrencyLimit(
    uniqueIds,
    TASK_READ_CONCURRENCY_LIMIT,
    async (taskId) => {
      const url = new URL(`${apiBaseUrl}/tasks/${taskId}`);

      try {
        const response = await fetch(url.toString(), { headers });
        snapshots[taskId] = await handleApiResponse(response);
      } catch (error) {
        snapshots[taskId] = handleApiError(error);
      }
    },
  );

  return snapshots;
};
